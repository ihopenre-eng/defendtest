import os
import uuid
import magic
import clamd
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from PIL import Image, UnidentifiedImageError

app = Flask(__name__)

# ==================== 보안 설정 ====================
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 최대 50MB

# PIL decompression bomb / pixel flood 방어 (DoS 방지)
Image.MAX_IMAGE_PIXELS = 100_000_000  # 약 10,000 × 10,000 픽셀 정도까지만 허용

# 웹 루트 외부의 안전한 저장 디렉토리
SECURE_UPLOAD_FOLDER = 'secure_uploads'
os.makedirs(SECURE_UPLOAD_FOLDER, exist_ok=True)

# 허용 확장자 (Whitelist)  docx 완전 제거 (매크로/XXE/SSRF 위험)
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf'}

# 허용 MIME 타입 (정확한 exact match로 강화)
ALLOWED_MIMES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf'
}

# ClamAV 시뮬레이션: Windows 환경 및 테스트 속도를 위한 시그니처 기반 다운그레이드 모킹
MALWARE_SIGNATURES = [
    b'<?php', b'<? ', b'<%', b'eval(', b'exec(', b'system(',
    b'passthru(', b'shell_exec(', b'base64_decode(', b'assert(',
    b'preg_replace', b'cmd.exe', b'/bin/sh', b'/bin/bash',
    b'powershell', b'WScript.Shell', b'CreateObject',
]

def allowed_extension(filename):
    """Layer 1: 확장자 Whitelist 검사"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def get_magic_mime(file_bytes):
    """Layer 3: Magic Number (파일 시그니처) 검사  bytes 기반으로 정확도 향상"""
    try:
        return magic.from_buffer(file_bytes[:2048], mime=True) if file_bytes else None
    except:
        return None


def scan_with_clamav(file_content: bytes) -> bool:
    """Layer 4: AV 시그니처 스캐닝 시뮬레이션 (ClamAV 모킹)"""
    # 실제 시스템 AV처럼 동작하도록 메모리 바이트를 직접 스캔
    try:
        content_lower = file_content.lower()
        for sig in MALWARE_SIGNATURES:
            if sig.lower() in content_lower:
                print(f"[-] ClamAV 시그니처 탐지: {sig}")
                return False  # 악성코드 탐지됨
        return True  # 안전
    except Exception as e:
        print(f"[-] AV 스캔 에러: {e} (fail-closed 적용으로 차단)")
        return False


@app.route('/upload', methods=['POST'])
def secure_upload():
    if 'file' not in request.files:
        return jsonify({"error": "파일이 없습니다."}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "파일명이 없습니다."}), 400

    original_filename = file.filename

    # ==================== Layer 1: 확장자 Whitelist ====================
    if not allowed_extension(original_filename):
        return jsonify({"error": "허용되지 않은 파일 확장자입니다."}), 403

    # ==================== Layer 2: MIME 타입 검사 (보조) ====================
    if file.content_type and file.content_type not in ALLOWED_MIMES:
        return jsonify({"error": "허용되지 않은 MIME 타입입니다."}), 403

    # 전체 파일 내용을 한 번만 읽음 (메모리 효율 + ClamAV/Magic 공용)
    file_content = file.read()
    if len(file_content) == 0:
        return jsonify({"error": "빈 파일입니다."}), 400

    # ==================== Layer 3: Magic Number 검사 (exact match + SVG 등 차단) ====================
    detected_mime = get_magic_mime(file_content)
    if detected_mime and detected_mime not in ALLOWED_MIMES:
        return jsonify({
            "error": "파일 시그니처(Magic Number)가 허용된 타입과 일치하지 않습니다. (SVG, script 등 차단)"
        }), 403

    # ==================== Layer 4: ClamAV 스캐닝 (fail-closed) ====================
    if not scan_with_clamav(file_content):
        return jsonify({"error": "악성코드가 탐지되었거나 AV 스캔에 실패했습니다."}), 403

    # ==================== Layer 5: 안전한 저장 처리 ====================
    # 이미지인 경우 무조건 .jpg로 강제 변환 (확장자 혼선 방지)
    if detected_mime and detected_mime.startswith('image/'):
        safe_ext = 'jpg'
    else:
        ext = secure_filename(original_filename).rsplit('.', 1)[-1].lower()
        safe_ext = ext

    safe_filename = f"{uuid.uuid4().hex}.{safe_ext}"
    save_path = os.path.join(SECURE_UPLOAD_FOLDER, safe_filename)

    # 이미지 처리 (metadata strip + RGB 변환 + 크기 제한)
    if detected_mime and detected_mime.startswith('image/'):
        try:
            # PIL로 다시 열기 (stream 위치 초기화)
            file.stream.seek(0)
            with Image.open(file.stream) as img:
                # pixel flood / decompression bomb 추가 방어
                if img.width * img.height > 100_000_000:
                    return jsonify({"error": "이미지 해상도가 너무 큽니다 (DoS 방어)."}), 403
                
                # 안전한 RGB 변환 + metadata 제거
                img = img.convert('RGB')
                img.save(save_path, 'JPEG', quality=85, optimize=True)
        except (UnidentifiedImageError, Exception) as e:
            print(f"[-] Image processing failed: {e}")
            return jsonify({"error": "이미지 처리 중 오류가 발생했습니다."}), 403
    else:
        # PDF 등 일반 파일은 그대로 저장
        with open(save_path, 'wb') as f:
            f.write(file_content)

    # 실행 권한 완전 제거 (644)
    os.chmod(save_path, 0o644)

    print(f"[+] 안전하게 저장됨: {safe_filename} (원본: {original_filename} | MIME: {detected_mime})")

    return jsonify({
        "message": "파일이 안전하게 업로드되었습니다.",
        "filename": safe_filename,
        "original_name": original_filename,
        "path": f"/files/{safe_filename}"
    }), 200


# ==================== 다운로드 라우트 (XSS 방지) ====================
@app.route('/files/<filename>')
def serve_file(filename):
    """보안 다운로드 라우트  Content-Type 정확 설정 + as_attachment=True (브라우저 실행 방지)"""
    safe_filename = secure_filename(filename)
    if safe_filename != filename or '..' in filename or '/' in filename or '\\' in filename:
        return jsonify({"error": "Invalid filename"}), 400

    file_path = os.path.join(SECURE_UPLOAD_FOLDER, safe_filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    # 확장자에 따라 정확한 MIME 설정
    if filename.endswith(('.jpg', '.jpeg')):
        mimetype = 'image/jpeg'
    elif filename.endswith('.png'):
        mimetype = 'image/png'
    elif filename.endswith('.gif'):
        mimetype = 'image/gif'
    elif filename.endswith('.pdf'):
        mimetype = 'application/pdf'
    else:
        mimetype = 'application/octet-stream'

    # as_attachment=True  브라우저에서 자동 실행(XSS) 방지
    return send_from_directory(
        SECURE_UPLOAD_FOLDER,
        safe_filename,
        mimetype=mimetype,
        as_attachment=True
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
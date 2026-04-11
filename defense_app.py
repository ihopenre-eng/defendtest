import os
import uuid
import magic
import hashlib
import struct
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from PIL import Image, UnidentifiedImageError
import io

app = Flask(__name__)

app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 
Image.MAX_IMAGE_PIXELS = 50_000_000  

SECURE_UPLOAD_FOLDER = 'secure_uploads'
os.makedirs(SECURE_UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf'}

ALLOWED_MIMES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf'
}

# ── 매직 바이트 정의 (오프셋, 바이트) ──────────────────────────────
MAGIC_SIGNATURES = {
    'image/jpeg': [(0, b'\xff\xd8\xff')],
    'image/png':  [(0, b'\x89PNG\r\n\x1a\n')],
    'image/gif':  [(0, b'GIF87a'), (0, b'GIF89a')],
    'application/pdf': [(0, b'%PDF-')],
}

# ── 폴리글랏/악성 패턴: 전체 파일 스캔 ───────────────────────────────
MALICIOUS_PATTERNS = [
    # PHP 변형
    b'<?php', b'<?\n', b'<? ', b'<?=',
    # 스크립트 태그 (SVG XSS)
    b'<script', b'javascript:',
    # 위험 함수
    b'eval(', b'exec(', b'system(', b'passthru(',
    b'shell_exec(', b'popen(', b'proc_open(',
    b'base64_decode(', b'assert(', b'preg_replace(',
    # 시스템 명령
    b'cmd.exe', b'/bin/sh', b'/bin/bash',
    b'powershell', b'WScript.Shell', b'CreateObject(',
    # Phar 폴리글랏
    b'__HALT_COMPILER',
    # Null byte 인젝션
    b'\x00.',
]


# ══════════════════════════════════════════════════════════
# Layer 1: 확장자 Whitelist (다중 확장자 차단 강화)
# ══════════════════════════════════════════════════════════
def check_extension(filename: str) -> bool:
    """
    다중 확장자 공격 차단: shell.php.jpg, shell.jpg.php 등
    → 마지막 확장자만 허용하되, 중간에 위험 확장자 있으면 차단
    """
    parts = filename.lower().split('.')
    if len(parts) < 2:
        return False
    
    DANGEROUS_EXTENSIONS = {
        'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar',
        'asp', 'aspx', 'jsp', 'jspx', 'cfm', 'cgi', 'pl',
        'py', 'rb', 'sh', 'bash', 'exe', 'dll', 'bat', 'cmd',
        'htaccess', 'htpasswd', 'ini', 'config', 'env'
    }
    
    # 모든 확장자 파트에 위험 확장자 있으면 차단
    for part in parts[1:]:
        if part in DANGEROUS_EXTENSIONS:
            return False
    
    # 마지막 확장자만 허용 목록 확인
    return parts[-1] in ALLOWED_EXTENSIONS


# ══════════════════════════════════════════════════════════
# Layer 2: MIME 헤더 검사 (Content-Type 스푸핑 탐지)
# ══════════════════════════════════════════════════════════
def check_content_type(content_type: str) -> bool:
    if not content_type:
        return False
    # 파라미터 제거: "image/jpeg; charset=utf-8" → "image/jpeg"
    mime = content_type.split(';')[0].strip().lower()
    return mime in ALLOWED_MIMES


# ══════════════════════════════════════════════════════════
# Layer 3 (강화): 매직 바이트 직접 검증 + 전체 파일 스캔
# ══════════════════════════════════════════════════════════
def check_magic_bytes(file_content: bytes) -> tuple[bool, str | None]:
    """
    python-magic 의존 없이 직접 매직 바이트 비교.
    → 라이브러리 우회 공격 방어
    """
    for mime_type, signatures in MAGIC_SIGNATURES.items():
        for offset, sig in signatures:
            if file_content[offset:offset + len(sig)] == sig:
                return True, mime_type
    return False, None


def check_magic_mime_lib(file_content: bytes) -> str | None:
    """python-magic 라이브러리 검사 (교차 검증용)"""
    try:
        # 전체 파일 검사로 변경 (핵심 수정)
        return magic.from_buffer(file_content, mime=True)
    except Exception:
        return None


def scan_malicious_patterns(file_content: bytes) -> tuple[bool, str]:
    """
    전체 파일에서 악성 패턴 검색 및 딥 익스트랙션 (Archive Unpacking) 시뮬레이션.
    대소문자 무시 + null byte 처리 + zlib 압축 해제 검사
    """
    content_lower = file_content.lower()
    content_no_null = file_content.replace(b'\x00', b'').lower()
    
    # 1. 원본 플랫 바이트 검사
    for pattern in MALICIOUS_PATTERNS:
        if pattern.lower() in content_lower or pattern.lower() in content_no_null:
            return False, pattern.decode('utf-8', 'ignore')
            
    # 2. 압축/아카이브 검사 (zlib)
    import zlib
    idx = 0
    while idx < len(file_content) - 10:
        if file_content[idx:idx+2] in [b'\x78\x01', b'\x78\x9c', b'\x78\xda']:
            try:
                decompressed = zlib.decompress(file_content[idx:])
                dec_lower = decompressed.lower()
                for pattern in MALICIOUS_PATTERNS:
                    if pattern.lower() in dec_lower:
                        return False, f"Zlib-compressed {pattern.decode('utf-8', 'ignore')}"
            except zlib.error:
                pass
        idx += 1
        
    return True, ""


# ══════════════════════════════════════════════════════════
# Layer 4: 이미지 재인코딩 (핵심 방어)
# ══════════════════════════════════════════════════════════
def sanitize_image(file_content: bytes, save_path: str) -> tuple[bool, str]:
    """
    PIL로 픽셀 데이터만 추출 후 재인코딩.
    → 메타데이터(EXIF), 숨겨진 페이로드, 폴리글랏 완전 제거
    """
    try:
        with Image.open(io.BytesIO(file_content)) as img:
            # 해상도 검사
            if img.width * img.height > 50_000_000:
                return False, "이미지 해상도 초과 (DoS 방어)"
            
            # 최소 크기 검사
            if img.width < 1 or img.height < 1:
                return False, "유효하지 않은 이미지 크기"
            
            # 픽셀 데이터만 추출 (페이로드 완전 제거)
            clean_img = img.convert('RGB')
            
            # 새 파일로 저장 (원본 바이트 일절 사용 안 함)
            clean_img.save(save_path, 'JPEG', quality=85, optimize=True)
            return True, "OK"
            
    except UnidentifiedImageError:
        return False, "PIL이 인식 불가한 이미지"
    except Exception as e:
        return False, f"이미지 처리 오류: {e}"


# ══════════════════════════════════════════════════════════
# Layer 5: PDF 검사 (별도 처리)
# ══════════════════════════════════════════════════════════
def cdr_sanitize_pdf(file_content: bytes) -> tuple[bool, bytes]:
    """
    Layer 5: PDF File Content Disarm and Reconstruction (CDR) 시뮬레이션
    단순 스트링 기반 악성 구문 스펙트럼 치환 및 정화
    """
    safe_content = file_content
    replacements = {
        b'<?php': b'<!--CDR_RM-->',
        b'eval(': b'CDR_RM(',
        b'system(': b'CDR_RM(',
        b'destruct': b'CDR_RM',
        b'/JavaScript': b'/RM_JS',
        b'/JS': b'/RM_JS',
        b'/OpenAction': b'/RM_Act',
        b'/AA ': b'/RM ',
        b'/Launch': b'/RM_Lch'
    }
    
    modified = False
    for risk, safe in replacements.items():
        if risk in safe_content:
            safe_content = safe_content.replace(risk, safe)
            modified = True
            
    return True, safe_content


# ══════════════════════════════════════════════════════════
# 메인 업로드 라우트
# ══════════════════════════════════════════════════════════
@app.route('/upload', methods=['POST'])
def secure_upload():
    if 'file' not in request.files:
        return jsonify({"error": "파일이 없습니다"}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({"error": "파일명이 없습니다"}), 400

    original_filename = secure_filename(file.filename)
    file_hash = None

    # ── Layer 1: 확장자 ──────────────────────────────────────
    if not check_extension(original_filename):
        return jsonify({"error": "L1: 허용되지 않은 확장자 또는 다중 확장자 공격"}), 403

    # ── Layer 2: Content-Type 헤더 ───────────────────────────
    if not check_content_type(file.content_type or ''):
        return jsonify({"error": "L2: 허용되지 않은 Content-Type"}), 403

    # 파일 읽기 (한 번만)
    file_content = file.read()
    if not file_content:
        return jsonify({"error": "빈 파일"}), 400

    file_hash = hashlib.sha256(file_content).hexdigest()

    # ── Layer 3a: 직접 매직 바이트 검증 ─────────────────────
    magic_ok, detected_type = check_magic_bytes(file_content)
    if not magic_ok:
        return jsonify({"error": "L3a: 매직 바이트 불일치"}), 403

    # ── Layer 3b: python-magic 교차 검증 ─────────────────────
    lib_mime = check_magic_mime_lib(file_content)
    if lib_mime and lib_mime != detected_type:
        return jsonify({
            "error": f"L3b: MIME 불일치 (직접검사={detected_type}, 라이브러리={lib_mime})"
        }), 403

    # ── Layer 3c: 전체 파일 악성 패턴 스캔 ───────────────────
    pattern_ok, found_pattern = scan_malicious_patterns(file_content)
    if not pattern_ok:
        return jsonify({"error": f"L3c: 악성 패턴 탐지: {found_pattern}"}), 403

    # ── Layer 4: 타입별 처리 ─────────────────────────────────
    safe_filename = f"{uuid.uuid4().hex}"
    
    if detected_type and detected_type.startswith('image/'):
        save_path = os.path.join(SECURE_UPLOAD_FOLDER, f"{safe_filename}.jpg")
        success, msg = sanitize_image(file_content, save_path)
        if not success:
            return jsonify({"error": f"L4: 이미지 재인코딩 실패: {msg}"}), 403
        final_filename = f"{safe_filename}.jpg"

    elif detected_type == 'application/pdf':
        pdf_ok, sanitized_pdf = cdr_sanitize_pdf(file_content)
        if not pdf_ok:
            return jsonify({"error": "L4: PDF CDR 정화 실패"}), 403
        save_path = os.path.join(SECURE_UPLOAD_FOLDER, f"{safe_filename}.pdf")
        with open(save_path, 'wb') as f:
            f.write(sanitized_pdf)
        final_filename = f"{safe_filename}.pdf"

    else:
        return jsonify({"error": "처리 불가 타입"}), 403

    # ── Layer 5: 권한 강화 ───────────────────────────────────
    os.chmod(save_path, 0o644)

    print(f"[+] 저장완료: {final_filename} | SHA256: {file_hash[:16]}... | MIME: {detected_type}")

    return jsonify({
        "message": "업로드 성공",
        "filename": final_filename,
        "sha256": file_hash,
        "detected_type": detected_type
    }), 200


# ── 다운로드 ─────────────────────────────────────────────────────────
@app.route('/files/<filename>')
def serve_file(filename):
    safe_filename = secure_filename(filename)
    if safe_filename != filename or '..' in filename or '/' in filename:
        return jsonify({"error": "잘못된 파일명"}), 400

    file_path = os.path.join(SECURE_UPLOAD_FOLDER, safe_filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "파일 없음"}), 404

    MIME_MAP = {
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png',  '.gif': 'image/gif',
        '.pdf': 'application/pdf',
    }
    ext = os.path.splitext(safe_filename)[1].lower()
    mimetype = MIME_MAP.get(ext, 'application/octet-stream')

    return send_from_directory(
        SECURE_UPLOAD_FOLDER, safe_filename,
        mimetype=mimetype,
        as_attachment=True,
        download_name=safe_filename
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

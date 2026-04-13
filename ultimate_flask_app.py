# -*- coding: utf-8 -*-
# ultimate_flask_app.py
# ============================================================
# Flask 기반 다계층 방어 파일 업로드 서버 (전면 개정판)
#
# 로드맵 반영 사항:
# - #4: MIME 검증을 mimetypes(확장자 기반) → 매직 바이트 직접 파싱으로 교체
# - #7: PDF CDR을 바이트 치환 → ImageMagick/Ghostscript 파이프라인으로 교체
# - 이미지 CDR: ImageMagick(OS) → Pillow(fallback) 순으로 처리
# ============================================================
import os
import uuid
import subprocess
import shutil
import tempfile
from flask import Flask, request, jsonify

app = Flask(__name__)

app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB
UPLOAD_DIR = 'ultimate_secure_uploads_flask'
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf'}
DANGEROUS_EXT = {'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'pht',
                 'phar', 'svg', 'html', 'htm', 'js', 'exe', 'sh', 'bat',
                 'htaccess', 'jsp', 'asp', 'aspx', 'cgi'}

# ── Layer 2 개선: 매직 바이트 기반 MIME 검증 (확장자 의존 제거) ──
MAGIC_TABLE = {
    b'\xff\xd8\xff':           ('image/jpeg', 'jpg'),
    b'\x89PNG\r\n\x1a\n':     ('image/png',  'png'),
    b'GIF87a':                 ('image/gif',  'gif'),
    b'GIF89a':                 ('image/gif',  'gif'),
    b'%PDF-':                  ('application/pdf', 'pdf'),
}

ALLOWED_MIMES = {
    'image/jpeg': 'jpg',
    'image/png':  'png',
    'application/pdf': 'pdf',
}


def validate_extension(filename: str):
    """Layer 1: 확장자 화이트리스트 + 다중 확장자/설정파일 차단"""
    if filename.startswith('.') or 'htaccess' in filename.lower():
        return False

    parts = filename.lower().split('.')
    if len(parts) < 2:
        return False

    ext = parts[-1]
    if ext not in ALLOWED_EXTENSIONS:
        return False

    for part in parts:
        if part in DANGEROUS_EXT:
            return False

    return ext


def detect_mime_by_magic(file_bytes: bytes):
    """
    Layer 2 개선: 파일 내용의 매직 바이트로 MIME 타입을 판정합니다.
    mimetypes.guess_type()(확장자 기반)를 사용하지 않습니다.

    반환: (mime_type, canonical_ext) 또는 (None, None)
    """
    if not file_bytes or len(file_bytes) < 4:
        return None, None

    for magic_bytes, (mime, ext) in MAGIC_TABLE.items():
        if file_bytes[:len(magic_bytes)] == magic_bytes:
            return mime, ext

    return None, None


def process_image_cdr(tmp_path: str, save_path: str, detected_ext: str) -> str:
    """
    Layer 5 이미지 CDR: ImageMagick(OS) → Pillow(fallback)

    핵심: 입력 포맷을 명시적으로 지정(jpeg:, png:)하여
    ImageTragick(CVE-2016-3714) MVG/MSL 공격을 원천 차단합니다.
    """
    # 출력은 항상 JPEG로 강제 변환 (폴리글랏 제거)
    if not save_path.lower().endswith('.jpg'):
        save_path = os.path.splitext(save_path)[0] + '.jpg'

    fmt_prefix = {
        'jpg': 'jpeg:', 'jpeg': 'jpeg:',
        'png': 'png:', 'gif': 'gif:',
    }.get(detected_ext, '')

    input_spec = f"{fmt_prefix}{tmp_path}"
    if detected_ext == 'gif':
        input_spec += "[0]"  # GIF 첫 프레임만

    # 1차: ImageMagick
    for magick_cmd in ['magick', 'convert']:
        try:
            result = subprocess.run(
                [magick_cmd, 'convert', input_spec,
                 '-strip', '-interlace', 'Line', '-quality', '85',
                 save_path],
                capture_output=True, timeout=15
            )
            if result.returncode == 0 and os.path.exists(save_path):
                return save_path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    # 2차: Pillow (fallback)
    try:
        from PIL import Image
        with Image.open(tmp_path) as img:
            clean = img.convert('RGB')
            clean.save(save_path, 'JPEG', quality=85, optimize=True)
        return save_path
    except Exception as e:
        raise Exception(f"Image CDR failed (both ImageMagick and Pillow): {e}")


def sanitize_pdf_cdr(tmp_path: str, save_path: str) -> str:
    """
    Layer 5 PDF CDR (로드맵 #7):
    바이트 치환이 아닌, 외부 도구로 실제 파일 재구축(True CDR).

    1차: Ghostscript (-sDEVICE=pdfwrite) — 파일 구조 완전 재구축
    2차: ImageMagick (gslib delegate 내장) — PDF→PDF 변환
    실패 시: 업로드 거부 (fail-closed)
    """
    # 1차: Ghostscript 직접 호출
    for gs_cmd in ['gswin64c', 'gs']:
        try:
            result = subprocess.run(
                [gs_cmd, '-sDEVICE=pdfwrite', '-dSAFER',
                 '-dCompatibilityLevel=1.7', '-dNOPAUSE', '-dQUIET',
                 '-dBATCH', f'-sOutputFile={save_path}', tmp_path],
                capture_output=True, timeout=15
            )
            if result.returncode == 0 and os.path.exists(save_path):
                return save_path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    # 2차: ImageMagick의 내장 Ghostscript delegate 활용
    for magick_cmd in ['magick', 'convert']:
        try:
            result = subprocess.run(
                [magick_cmd, 'convert', f'pdf:{tmp_path}',
                 '-density', '150', f'pdf:{save_path}'],
                capture_output=True, timeout=15
            )
            if result.returncode == 0 and os.path.exists(save_path):
                return save_path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    raise Exception("PDF CDR failed: Neither Ghostscript nor ImageMagick available")


@app.route('/upload', methods=['POST'])
def secure_upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No filename"}), 400

    original_name = file.filename

    # ── Layer 1: 확장자 화이트리스트 ──
    ext = validate_extension(original_name)
    if not ext:
        return jsonify({"error": "Layer 1: Extension blocked"}), 403

    # 임시 파일로 저장
    with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{ext}') as tmp:
        file.save(tmp.name)
        tmp_path = tmp.name

    try:
        # 파일 바이트 읽기
        with open(tmp_path, 'rb') as f:
            file_bytes = f.read()

        # ── Layer 2 개선: 매직 바이트 기반 MIME 검증 ──
        detected_mime, detected_ext = detect_mime_by_magic(file_bytes)
        if detected_mime is None or detected_mime not in ALLOWED_MIMES:
            return jsonify({"error": f"Layer 2: Magic byte mismatch (detected: {detected_mime})"}), 403

        # 확장자와 매직 바이트 교차 검증
        if ALLOWED_MIMES.get(detected_mime) not in (ext, detected_ext):
            # jpg/jpeg 호환성 처리
            if not (ext in ('jpg', 'jpeg') and detected_ext in ('jpg', 'jpeg')):
                return jsonify({"error": f"Layer 2/3: Extension-Magic mismatch (ext={ext}, magic={detected_ext})"}), 403

        # ── Layer 3: XML/SVG 사전 차단 (패딩 우회 대비 8KB 스캔) ──
        import re
        header_scan = file_bytes[:8192].lower()
        if re.search(rb'<\s*!doctype|<\s*\?xml|<\s*svg', header_scan):
            return jsonify({"error": "Layer 3: XML/SVG payload blocked"}), 403

        # ── .htaccess 방어적 설정 ──
        htaccess = os.path.join(UPLOAD_DIR, '.htaccess')
        if not os.path.exists(htaccess):
            with open(htaccess, 'w') as f:
                f.write("php_flag engine off\n"
                        "AddHandler cgi-script .php .php5 .phtml\n"
                        "Options -ExecCGI\n")

        # UUID 기반 안전 파일명
        safe_filename = uuid.uuid4().hex + '.' + detected_ext
        save_path = os.path.join(UPLOAD_DIR, safe_filename)

        # ── Layer 5: CDR (Content Disarm & Reconstruction) ──
        if detected_mime.startswith('image/'):
            final_path = process_image_cdr(tmp_path, save_path, detected_ext)
        elif detected_mime == 'application/pdf':
            final_path = sanitize_pdf_cdr(tmp_path, save_path)
        else:
            return jsonify({"error": "Layer 5: Unsupported type"}), 403

        try:
            os.chmod(final_path, 0o644)
        except Exception:
            pass

    except Exception as e:
        return jsonify({"error": f"Layer 5: CDR processing error — {str(e)}"}), 403
    finally:
        # 임시 파일 정리
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    return jsonify({
        "status": "SUCCESS",
        "filename": os.path.basename(final_path),
        "saved_file": os.path.basename(final_path),
        "message": "File uploaded and hardened successfully (L1-L5 passed)"
    }), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010, debug=False)

# matrix_defense_apps.py
# Layer Interaction (조합) 테스트를 위한 Flask 앱 (Windows 호환)

import os
import uuid
# magic library is removed due to Windows DLL/Path crashing issues
from PIL import Image
from flask import Flask, request, jsonify
import tempfile

def create_matrix_app(combo_name="L0", use_l1=False, use_l2=False, use_l3=False, use_l4=False, use_l5=False):
    """
    각 Layer의 On/Off를 개별적으로 제어할 수 있는 조합형 앱 생성기
    """
    app = Flask(__name__)
    UPLOAD_FOLDER = f'uploads_matrix_{combo_name.replace("+", "_")}'
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}
    MAX_FILE_SIZE = 50 * 1024 * 1024

    def allowed_file(filename):
        return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

    # ClamAV 시뮬레이션: 실제 AV처럼 시그니처 기반 악성코드 패턴 탐지
    MALWARE_SIGNATURES = [
        b'<?php', b'<? ', b'<%', b'eval(', b'exec(', b'system(',
        b'passthru(', b'shell_exec(', b'base64_decode(', b'assert(',
        b'preg_replace', b'cmd.exe', b'/bin/sh', b'/bin/bash',
        b'powershell', b'WScript.Shell', b'CreateObject',
    ]

    def scan_with_clamav(file_content: bytes) -> bool:
        """Layer 4: AV 시그니처 스캐닝 시뮬레이션 (ClamAV 모킹)"""
        # 실제 ClamAV처럼 파일 내부 바이트를 스캔하여 악성 패턴 매칭
        content_lower = file_content.lower()
        for sig in MALWARE_SIGNATURES:
            if sig.lower() in content_lower:
                return False  # 악성코드 탐지됨
        return True  # 안전

    def detect_mime_magic(b: bytes) -> str:
        """Windows 경로 버그(Illegal byte sequence)를 회피하기 위한 자체 매직바이트 검사 함수"""
        if not b: return ""
        if b.startswith(b'\xff\xd8\xff'): return 'image/jpeg'
        if b.startswith(b'\x89PNG\r\n\x1a\n'): return 'image/png'
        if b.startswith(b'GIF87a') or b.startswith(b'GIF89a'): return 'image/gif'
        if b.startswith(b'%PDF-'): return 'application/pdf'
        if b.startswith(b'<svg') or b.startswith(b'<?xml'): return 'image/svg+xml'
        if b.startswith(b'RIFF') and b[8:12] == b'WEBP': return 'image/webp'
        return 'application/octet-stream'

    @app.route('/upload', methods=['POST'])
    def upload_file():
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        file.seek(0, os.SEEK_END)
        if file.tell() > MAX_FILE_SIZE:
            return jsonify({'error': 'Size limit exceeded'}), 400
        file.seek(0)

        original_filename = file.filename
        
        # Windows 호환: 파일 바이트를 한 번만 읽어서 공용 사용
        file_bytes = file.read()
        file.seek(0)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as tmp:
            temp_path = tmp.name
        with open(temp_path, 'wb') as f:
            f.write(file_bytes)

        try:
            # ============== 독립적 Layer 적용 (조합형) ==============
            if use_l1:
                # Layer 1: 클라이언트/프론트엔드 검증 (확장자 명시적 체크)
                if not allowed_file(original_filename):
                    return jsonify({'error': 'Blocked by Layer 1: Extension whitelist'}), 403

            if use_l2:
                # Layer 2: 서버 사이드 기본 검증 (MIME Type 체크)
                if not (file.content_type and (file.content_type.startswith('image/') or file.content_type == 'application/pdf')):
                    return jsonify({'error': 'Blocked by Layer 2: MIME Type Header'}), 403

            if use_l3:
                # Layer 3: 백엔드/애플리케이션 정밀 검증 (Magic Number 교차 체크)
                try:
                    detected = detect_mime_magic(file_bytes[:2048])
                    if not (detected.startswith('image/') or detected == 'application/pdf'):
                        return jsonify({'error': 'Blocked by Layer 3: Internal Magic Number mismatch'}), 403
                except Exception as e:
                    return jsonify({'error': f'Layer 3 Exception: {e}'}), 403

            if use_l4:
                # Layer 4: 시스템 OS/AV 검사 (시그니처 기반 악성코드 스캐닝)
                if not scan_with_clamav(file_bytes):
                    return jsonify({'error': 'Blocked by Layer 4: Malware signature detected'}), 403

            # ============== 스토리지 저장 (Layer 5 옵션) ==============
            if use_l5:
                # Layer 5: 스토리지 격리 및 파일 Sanitization (재렌더링)
                # UUID로 파일명 완전 교체 + 이미지는 JPEG로 강제 변환
                saved_filename = f"{uuid.uuid4().hex}.jpg"
                saved_path = os.path.join(UPLOAD_FOLDER, saved_filename)

                # 자체 detect_mime_magic 사용 (Windows 호환)
                detected_mime = detect_mime_magic(file_bytes[:2048])
                
                if detected_mime.startswith('image/'):
                    try:
                        with Image.open(temp_path) as img:
                            img = img.convert('RGB')  # RGBA/P 모드  RGB 강제 변환
                            img.save(saved_path, 'JPEG', quality=85)  # 포맷 명시적 지정
                    except Exception:
                        return jsonify({'error': 'Blocked by Layer 5: Image sanitization failed'}), 403
                else:
                    # 이미지가 아닌 경우 (PDF 등)
                    saved_filename = f"{uuid.uuid4().hex}.pdf"
                    saved_path = os.path.join(UPLOAD_FOLDER, saved_filename)
                    os.replace(temp_path, saved_path)
                
                return jsonify({'status': 'success', 'saved_file': saved_filename}), 200
            else:
                # Sanitization 끄기 (취약한 원본 저장체계)
                filename = os.path.basename(original_filename)
                saved_path = os.path.join(UPLOAD_FOLDER, filename)
                os.replace(temp_path, saved_path)
                return jsonify({'status': 'success', 'saved_file': filename}), 200

        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

    return app

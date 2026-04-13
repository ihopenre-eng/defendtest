<?php
// ultimate_defense_app.php — PHP 다계층 방어 파일 업로드 서버 (전면 개정판)
//
// 로드맵 반영:
// - #2: PHP GD/fileinfo 확장 모듈 활용 (php.ini 경로 수정으로 로딩 보장)
// - #4: finfo(libmagic) 기반 진정한 MIME 검증
// - #7: ImageMagick CLI + GD fallback으로 True CDR 구현
//
// 실행: php -c php.ini -S 127.0.0.1:5008 ultimate_defense_app.php

ini_set('display_errors', 0);
error_reporting(E_ALL);

define('UPLOAD_DIR', __DIR__ . '/ultimate_secure_uploads/');
define('MAX_FILE_SIZE', 10 * 1024 * 1024);
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'pdf']);
const DANGEROUS_EXT = ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'pht',
    'phar', 'svg', 'html', 'htm', 'js', 'exe', 'sh', 'bat',
    'htaccess', 'jsp', 'asp', 'aspx', 'cgi'];

function log_error($msg) {
    error_log("[UPLOAD_BLOCK] " . $msg);
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(["error" => $msg]);
    exit;
}

// ── Layer 1: 확장자 화이트리스트 (다중 확장자 + 설정파일 차단) ──
function validate_extension($filename) {
    if (strpos($filename, '.') === 0 || stripos($filename, 'htaccess') !== false) {
        return false;
    }
    $parts = explode('.', strtolower($filename));
    if (count($parts) < 2) return false;

    $ext = end($parts);
    if (!in_array($ext, ALLOWED_EXTENSIONS)) return false;

    foreach ($parts as $part) {
        if (in_array($part, DANGEROUS_EXT)) return false;
    }
    return $ext;
}

// ── Layer 2: finfo(libmagic) 기반 MIME 검증 (로드맵 #4) ──
function validate_mime($tmp_path) {
    $allowed_mimes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'application/pdf' => 'pdf'
    ];

    $mime = null;

    // 1차: finfo (libmagic) — 파일 내용 기반 진정한 MIME 검증
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $tmp_path);
        finfo_close($finfo);
    }

    // 2차: 직접 매직 바이트 검사 (fallback)
    if (!$mime) {
        $handle = fopen($tmp_path, 'rb');
        $bytes = fread($handle, 8);
        fclose($handle);

        if (substr($bytes, 0, 3) === "\xFF\xD8\xFF") $mime = 'image/jpeg';
        elseif (substr($bytes, 0, 4) === "\x89PNG") $mime = 'image/png';
        elseif (substr($bytes, 0, 4) === "%PDF") $mime = 'application/pdf';
    }

    if (!$mime || !array_key_exists($mime, $allowed_mimes)) {
        return false;
    }
    return $allowed_mimes[$mime];
}

// ── Layer 5 이미지 CDR: ImageMagick → GD fallback ──
function process_image_cdr($tmp_path, $save_path, $ext) {
    // 항상 JPEG로 강제 변환 (폴리글랏 제거)
    $output_path = preg_replace('/\.[^.]+$/', '.jpg', $save_path);
    if (!str_ends_with($output_path, '.jpg')) {
        $output_path .= '.jpg';
    }

    // 입력 포맷 명시 (CVE-2016-3714 ImageTragick 방어)
    $fmt_map = ['jpg' => 'jpeg:', 'jpeg' => 'jpeg:', 'png' => 'png:', 'gif' => 'gif:'];
    $fmt_prefix = $fmt_map[$ext] ?? '';
    $input_spec = $fmt_prefix . $tmp_path;
    if ($ext === 'gif') $input_spec .= '[0]';

    // 1차: ImageMagick CLI
    $magick_cmds = [
        "magick convert " . escapeshellarg($input_spec) .
        " -strip -interlace Line -quality 85 " . escapeshellarg($output_path),
        "convert " . escapeshellarg($input_spec) .
        " -strip -interlace Line -quality 85 " . escapeshellarg($output_path),
    ];

    foreach ($magick_cmds as $cmd) {
        exec($cmd . " 2>&1", $output, $ret);
        if ($ret === 0 && file_exists($output_path)) {
            return $output_path;
        }
    }

    // 2차: PHP GD (fallback)
    if ($ext === 'jpg' || $ext === 'jpeg') {
        $img = @imagecreatefromjpeg($tmp_path);
    } elseif ($ext === 'png') {
        $img = @imagecreatefrompng($tmp_path);
    } elseif ($ext === 'gif') {
        $img = @imagecreatefromgif($tmp_path);
    } else {
        $img = false;
    }

    if ($img) {
        imagejpeg($img, $output_path, 85);
        imagedestroy($img);
        return $output_path;
    }

    log_error("Layer 5: Image CDR failed — both ImageMagick and GD unavailable/failed");
    return false;
}

// ── Layer 5 PDF CDR: Ghostscript → ImageMagick delegate (로드맵 #7) ──
function sanitize_pdf_cdr($tmp_path, $save_path) {
    // 1차: Ghostscript 직접 호출 (True CDR — 파일 구조 완전 재구축)
    $gs_cmds = [
        "gswin64c -sDEVICE=pdfwrite -dSAFER -dCompatibilityLevel=1.7 " .
        "-dNOPAUSE -dQUIET -dBATCH -sOutputFile=" .
        escapeshellarg($save_path) . " " . escapeshellarg($tmp_path),

        "gs -sDEVICE=pdfwrite -dSAFER -dCompatibilityLevel=1.7 " .
        "-dNOPAUSE -dQUIET -dBATCH -sOutputFile=" .
        escapeshellarg($save_path) . " " . escapeshellarg($tmp_path),
    ];

    foreach ($gs_cmds as $cmd) {
        exec($cmd . " 2>&1", $output, $ret);
        if ($ret === 0 && file_exists($save_path)) {
            return $save_path;
        }
    }

    // 2차: ImageMagick의 내장 Ghostscript delegate 활용
    $magick_cmds = [
        "magick convert " . escapeshellarg("pdf:" . $tmp_path) .
        " -density 150 " . escapeshellarg("pdf:" . $save_path),
        "convert " . escapeshellarg("pdf:" . $tmp_path) .
        " -density 150 " . escapeshellarg("pdf:" . $save_path),
    ];

    foreach ($magick_cmds as $cmd) {
        exec($cmd . " 2>&1", $output, $ret);
        if ($ret === 0 && file_exists($save_path)) {
            return $save_path;
        }
    }

    log_error("Layer 5: PDF CDR failed — neither Ghostscript nor ImageMagick gs-delegate available");
    return false;
}


// ══════════════════════════════════════════════════════════════
// Main Upload Handler
// ══════════════════════════════════════════════════════════════
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_FILES['file'])) {
    http_response_code(400);
    die(json_encode(["error" => "No file uploaded"]));
}

header('Content-Type: application/json');

$file = $_FILES['file'];

if ($file['size'] > MAX_FILE_SIZE || $file['error'] !== UPLOAD_ERR_OK) {
    log_error("File too large or upload error");
}

$original_name = $file['name'];
$tmp_path = $file['tmp_name'];

// ── Layer 1: 확장자 화이트리스트 ──
$ext = validate_extension($original_name);
if (!$ext) {
    log_error("Layer 1: Extension blocked");
}

// ── Layer 3: XML/SVG 사전 차단 (패딩 우회 대비 8KB 스캔) ──
$header = @file_get_contents($tmp_path, false, null, 0, 8192);
if ($header) {
    $headerLower = strtolower($header);
    if (preg_match('/<\s*!doctype|<\s*\?xml|<\s*svg/i', $headerLower)) {
        log_error("Layer 3: XML/SVG payload blocked");
    }
}

// ── Layer 2: finfo 기반 MIME 검증 ──
$detected_ext = validate_mime($tmp_path);
if (!$detected_ext) {
    log_error("Layer 2: MIME/Magic byte mismatch — file content does not match any allowed type");
}
// 확장자-MIME 교차 검증
$ext_compat = ($ext === $detected_ext) ||
              (in_array($ext, ['jpg', 'jpeg']) && in_array($detected_ext, ['jpg', 'jpeg']));
if (!$ext_compat) {
    log_error("Layer 2/3: Extension-MIME mismatch (ext={$ext}, detected={$detected_ext})");
}

// ── 스토리지 준비 ──
if (!is_dir(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0755, true);
}

// 방어적 .htaccess (PHP 실행 차단)
$htaccess = UPLOAD_DIR . '.htaccess';
if (!file_exists($htaccess)) {
    file_put_contents($htaccess,
        "php_flag engine off\nAddHandler cgi-script .php .php5 .phtml\nOptions -ExecCGI\n");
    @chmod($htaccess, 0644);
}

$safe_filename = bin2hex(random_bytes(16)) . '.' . $detected_ext;
$save_path = UPLOAD_DIR . $safe_filename;

// ── Layer 5: CDR 처리 ──
if (in_array($detected_ext, ['jpg', 'jpeg', 'png', 'gif'])) {
    $final_path = process_image_cdr($tmp_path, $save_path, $detected_ext);
} elseif ($detected_ext === 'pdf') {
    $final_path = sanitize_pdf_cdr($tmp_path, $save_path);
} else {
    log_error("Layer 5: Unsupported type for CDR");
}

if (!$final_path || !file_exists($final_path)) {
    log_error("Layer 5: CDR output file not created");
}

@chmod($final_path, 0644);

echo json_encode([
    "status" => "SUCCESS",
    "filename" => basename($final_path),
    "saved_file" => basename($final_path),
    "message" => "File uploaded and hardened successfully (L1-L5 passed)"
]);
?>

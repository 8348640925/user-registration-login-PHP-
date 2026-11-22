<?php
/* ------------------------------------------------------------------
 * XAMPP quick setup
 *  1. Start Apache and MySQL in the XAMPP Control Panel.
 *  2. Put this folder in  C:\xampp\htdocs\user-portal
 *  3. Open  http://localhost/user-portal/
 * The database and tables are created automatically on first load.
 * ------------------------------------------------------------------ */

if (PHP_VERSION_ID < 70400) {
    exit('This project needs PHP 7.4 or newer. Please update XAMPP.');
}
if (!extension_loaded('pdo_mysql')) {
    exit('The pdo_mysql extension is off. In XAMPP open php.ini and enable extension=pdo_mysql, then restart Apache.');
}

date_default_timezone_set('Asia/Kolkata');

// Default XAMPP values: user "root", empty password, port 3306.
$db_host = '127.0.0.1';   // 127.0.0.1 works on Windows, macOS and Linux XAMPP
$db_port = 3306;          // change to 3307 if the XAMPP panel shows MySQL on 3307
$db_name = 'user_auth';
$db_user = 'root';
$db_pass = '';
$debug   = true;          // shows technical error details; set to false on a live server

$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET time_zone = '+05:30'",
];

function db_fail(PDOException $e): void {
    global $debug, $db_port;
    http_response_code(500);
    $detail = $debug ? '<p><small>Details: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . '</small></p>' : '';
    exit('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Database error</title></head>'
        . '<body style="font-family:system-ui,sans-serif;max-width:560px;margin:60px auto;padding:0 16px;line-height:1.6">'
        . '<h1>Cannot connect to MySQL</h1><ol>'
        . '<li>Open the <strong>XAMPP Control Panel</strong> and click <strong>Start</strong> next to MySQL.</li>'
        . '<li>If MySQL runs on another port (for example 3307), change <code>$db_port</code> in <code>config.php</code>. Current port: ' . (int)$db_port . '.</li>'
        . '<li>If you set a MySQL root password, put it in <code>$db_pass</code> in <code>config.php</code>.</li></ol>'
        . $detail . '</body></html>');
}

try {
    $pdo = new PDO("mysql:host={$db_host};port={$db_port};dbname={$db_name};charset=utf8mb4", $db_user, $db_pass, $options);
} catch (PDOException $e) {
    if ((int)($e->errorInfo[1] ?? 0) === 1049) {   // database does not exist yet: create it
        try {
            $server = new PDO("mysql:host={$db_host};port={$db_port};charset=utf8mb4", $db_user, $db_pass, $options);
            $server->exec("CREATE DATABASE IF NOT EXISTS `{$db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            $pdo = new PDO("mysql:host={$db_host};port={$db_port};dbname={$db_name};charset=utf8mb4", $db_user, $db_pass, $options);
        } catch (PDOException $e2) {
            db_fail($e2);
        }
    } else {
        db_fail($e);
    }
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => !empty($_SERVER['HTTPS']),
    ]);
    session_start();
}

/* Creates missing tables/columns and the default admin (safe to run many times). */
function ensure_schema(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(80) NOT NULL,
        email VARCHAR(190) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        is_blocked TINYINT(1) NOT NULL DEFAULT 0,
        last_login_at DATETIME NULL,
        login_count INT UNSIGNED NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS admins (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(190) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS login_logs (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NULL,
        email VARCHAR(190) NOT NULL,
        role ENUM('admin','user') NOT NULL DEFAULT 'user',
        status ENUM('success','failed','blocked') NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent VARCHAR(255) NOT NULL DEFAULT '',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_created (created_at),
        INDEX idx_ip_status (ip_address, status, created_at)
    )");

    $cols = [
        'is_blocked'    => 'TINYINT(1) NOT NULL DEFAULT 0',
        'last_login_at' => 'DATETIME NULL',
        'login_count'   => 'INT UNSIGNED NOT NULL DEFAULT 0',
    ];
    $check = $pdo->prepare("SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = ?");
    foreach ($cols as $name => $def) {
        $check->execute([$name]);
        if (!(int)$check->fetchColumn()) {
            $pdo->exec("ALTER TABLE users ADD COLUMN {$name} {$def}");
        }
    }

    if (!(int)$pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn()) {
        $pdo->prepare('INSERT INTO admins (email, password) VALUES (?, ?)')
            ->execute(['admin@123', password_hash('admin123', PASSWORD_DEFAULT)]);
    }
}

if (empty($_SESSION['schema_ok'])) {
    ensure_schema($pdo);
    $_SESSION['schema_ok'] = true;
}

function is_logged_in(): bool {
    return isset($_SESSION['user_id']);
}

function is_admin(): bool {
    return isset($_SESSION['admin_id']);
}

function require_admin(): void {
    no_cache();
    if (!is_admin()) {
        header('Location: ../login.php');
        exit;
    }
}

function e(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(): void {
    $token = $_POST['csrf_token'] ?? '';
    $known = $_SESSION['csrf_token'] ?? '';
    if (!is_string($token) || $token === '' || !is_string($known) || $known === '' || !hash_equals($known, $token)) {
        http_response_code(403);
        exit('Invalid request. Please go back and try again.');
    }
}

function no_cache(): void {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
}

function client_ip(): string {
    return substr($_SERVER['REMOTE_ADDR'] ?? 'unknown', 0, 45);
}

function log_login(PDO $pdo, ?int $userId, string $email, string $role, string $status): void {
    $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
    $pdo->prepare('INSERT INTO login_logs (user_id, email, role, status, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)')
        ->execute([$userId, substr($email, 0, 190), $role, $status, client_ip(), $ua]);
}

function flash_set(string $type, string $message): void {
    $_SESSION['flash'] = ['type' => $type, 'msg' => $message];
}

function flash_get(): ?array {
    $f = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return $f;
}

function format_dt(?string $value): string {
    return $value ? date('d M Y, h:i A', strtotime($value)) : '—';
}

/* Returns a list of problems with a new password (empty list = acceptable). */
function password_is_easy(string $pw): bool {
    $l = strtolower($pw);
    if (preg_match('/(.)\1{2,}/', $l)) {            // aaa, 1111
        return true;
    }
    $seqs = ['0123456789', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
    for ($i = 0; $i <= strlen($l) - 4; $i++) {      // 1234, abcd, dcba, qwer ...
        $chunk = substr($l, $i, 4);
        foreach ($seqs as $s) {
            if (strpos($s, $chunk) !== false || strpos(strrev($s), $chunk) !== false) {
                return true;
            }
        }
    }
    foreach (['password', 'passw0rd', 'admin', 'welcome', 'letmein', 'iloveyou', 'login', 'qwerty'] as $w) {
        if (strpos($l, $w) !== false) {
            return true;
        }
    }
    return false;
}

function password_problems(string $pw): array {
    if (strlen($pw) < 8) {
        return ['Password must contain at least 8 characters.'];
    }
    if (strlen($pw) > 72) {
        return ['Password must be 72 characters or fewer.'];
    }
    if (!preg_match('/[a-z]/', $pw) || !preg_match('/[A-Z]/', $pw) || !preg_match('/\d/', $pw) || !preg_match('/[^A-Za-z0-9]/', $pw)) {
        return ['Password must include an uppercase letter, a lowercase letter, a number and a special character (such as @ # $ !).'];
    }
    if (password_is_easy($pw)) {
        return ['This password is too easy to guess. Avoid sequences like 12345678 or abcd, repeated characters and common words.'];
    }
    return [];
}

<?php
declare(strict_types=1);

/**
 * FOS-Streaming FULLY COMPATIBLE Configuration
 * Maintains 100% backward compatibility while adding security
 */

// Start session securely but maintain compatibility
if (session_status() === PHP_SESSION_NONE) {
    // Enhanced security settings
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_secure', '0'); // Allow HTTP for compatibility
    ini_set('session.cookie_samesite', 'Lax'); // Less strict for compatibility
    ini_set('session.use_strict_mode', '1');
    ini_set('session.gc_maxlifetime', '7200'); // 2 hours
    ini_set('session.name', 'PHPSESSID'); // Keep standard name for compatibility
    
    session_start();
    
    // Session regeneration (less aggressive for compatibility)
    if (!isset($_SESSION['created'])) {
        $_SESSION['created'] = time();
    } elseif (time() - $_SESSION['created'] > 1800) { // 30 minutes
        session_regenerate_id(false); // Don't delete old session for compatibility
        $_SESSION['created'] = time();
    }
}

// Set timezone (maintain compatibility with existing)
date_default_timezone_set('Europe/Stockholm');

// COMPATIBILITY: Check for .env file but fallback to old method
$useEnvConfig = false;
$config = [];

if (file_exists(__DIR__ . '/.env')) {
    // NEW: Load from .env if available
    $envFile = __DIR__ . '/.env';
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    
    if ($lines !== false) {
        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) continue;
            
            if (strpos($line, '=') !== false) {
                [$key, $value] = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value, '"\'');
                
                if (preg_match('/^[A-Z_][A-Z0-9_]*$/', $key)) {
                    $config[$key] = $value;
                    $_ENV[$key] = $value;
                }
            }
        }
        $useEnvConfig = true;
    }
}

// Load required files
require __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/functions.php';

use Philo\Blade\Blade;
use Illuminate\Database\Capsule\Manager as Capsule;

// Template setup (maintain exact compatibility)
$views = __DIR__ . '/views';
$cache = __DIR__ . '/cache';
$template = new Blade($views, $cache);

// Database configuration with backward compatibility
$capsule = new Capsule;

if ($useEnvConfig) {
    // NEW: Use .env configuration
    $dbConfig = [
        'driver'    => 'mysql',
        'host'      => $config['DB_HOST'] ?? 'localhost',
        'database'  => $config['DB_DATABASE'] ?? 'fos',
        'username'  => $config['DB_USERNAME'] ?? 'fos',
        'password'  => $config['DB_PASSWORD'] ?? '',
        'charset'   => 'utf8mb4',
        'collation' => 'utf8mb4_unicode_ci',
        'prefix'    => $config['DB_PREFIX'] ?? '',
    ];
} else {
    // OLD: Maintain exact original configuration for compatibility
    $dbConfig = [
        'driver'    => 'mysql',
        'host'      => 'localhost',
        'database'  => 'xxx', // Will be replaced by install script
        'username'  => 'ttt', // Will be replaced by install script  
        'password'  => 'zzz', // Will be replaced by install script
        'charset'   => 'utf8',
        'collation' => 'utf8_unicode_ci',
        'prefix'    => '',
    ];
}

// Enhanced database configuration with compatibility
$dbConfig['strict'] = false; // Maintain MySQL compatibility
$dbConfig['options'] = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
    PDO::ATTR_TIMEOUT => 30
];

try {
    $capsule->addConnection($dbConfig);
    $capsule->setAsGlobal();
    $capsule->bootEloquent();
    
    // Test connection
    $capsule->getConnection()->getPdo();
    
} catch (Exception $e) {
    // Fallback error handling
    if (!headers_sent()) {
        if ($useEnvConfig) {
            error_log('Database connection failed: ' . $e->getMessage());
            die('Database connection error. Check configuration.');
        } else {
            // In development/first install, show helpful message
            die('Database connection failed. Please run the installation script.');
        }
    }
}

// COMPATIBILITY: Set global constants that might be expected
if ($useEnvConfig) {
    define('APP_KEY', $config['APP_KEY'] ?? '');
    define('FFMPEG_PATH', $config['FFMPEG_PATH'] ?? '/usr/local/bin/ffmpeg');
    define('FFPROBE_PATH', $config['FFPROBE_PATH'] ?? '/usr/local/bin/ffprobe');
    define('HLS_FOLDER', $config['HLS_FOLDER'] ?? 'hl');
    define('USER_AGENT', $config['USER_AGENT'] ?? 'FOS-Streaming');
}

// Security headers (only if not already sent)
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN'); // Less restrictive for compatibility
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // Less restrictive CSP for compatibility with existing code
    $csp = "default-src 'self' 'unsafe-inline' 'unsafe-eval'; " .
           "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " .
           "style-src 'self' 'unsafe-inline'; " .
           "img-src 'self' data: https: http:; " .
           "font-src 'self' data:; " .
           "connect-src 'self';";
    
    header("Content-Security-Policy: $csp");
}

// COMPATIBILITY FUNCTIONS for backward compatibility
function getConfig(string $key, $default = null)
{
    return $_ENV[$key] ?? $default;
}

function isProduction(): bool
{
    return (getConfig('APP_ENV') === 'production');
}

function isDebugMode(): bool
{
    return (getConfig('APP_DEBUG', 'false') === 'true') && !isProduction();
}

// Rate limiting functions (backward compatible)
function checkRateLimit(string $ip): bool
{
    $cacheFile = sys_get_temp_dir() . '/fos_rate_limit_' . md5($ip);
    
    if (file_exists($cacheFile)) {
        $data = json_decode(file_get_contents($cacheFile), true);
        
        if ($data && isset($data['attempts'], $data['timestamp'])) {
            // Reset after 15 minutes (was LOCKOUT_TIME)
            if (time() - $data['timestamp'] > 900) {
                unlink($cacheFile);
                return true;
            }
            
            // Max 5 attempts (was MAX_LOGIN_ATTEMPTS)
            if ($data['attempts'] >= 5) {
                return false;
            }
        }
    }
    
    return true;
}

function recordFailedLogin(string $ip): void
{
    $cacheFile = sys_get_temp_dir() . '/fos_rate_limit_' . md5($ip);
    $attempts = 1;
    
    if (file_exists($cacheFile)) {
        $data = json_decode(file_get_contents($cacheFile), true);
        if ($data && isset($data['attempts'])) {
            $attempts = $data['attempts'] + 1;
        }
    }
    
    $data = [
        'attempts' => $attempts,
        'timestamp' => time()
    ];
    
    file_put_contents($cacheFile, json_encode($data), LOCK_EX);
}

function clearRateLimit(string $ip): void
{
    $cacheFile = sys_get_temp_dir() . '/fos_rate_limit_' . md5($ip);
    if (file_exists($cacheFile)) {
        unlink($cacheFile);
    }
}

// CSRF token functions (backward compatible)
function generateCSRFToken(): string
{
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken(string $token): bool
{
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Logging function (safe fallback)
function logSecurityEvent(string $event, array $context = []): void
{
    $logData = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event' => $event,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'context' => $context
    ];
    
    // Try to log to file, but don't break if it fails
    $logFile = '/var/log/fos-streaming/security.log';
    if (is_dir(dirname($logFile)) && is_writable(dirname($logFile))) {
        file_put_contents($logFile, json_encode($logData) . "\n", FILE_APPEND | LOCK_EX);
    }
    
    // Always log to error log as fallback
    error_log('FOS-SECURITY: ' . $event . ' - ' . json_encode($context));
}

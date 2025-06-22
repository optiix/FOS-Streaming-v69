<?php
declare(strict_types=1);

/**
 * FOS-Streaming Secure Playlist Generator
 * PHP 8.1+ compatible with comprehensive security enhancements
 * SECURITY HARDENED VERSION
 */

// Security headers first
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// Include config
require_once 'config.php';

// Security configuration
set_time_limit(300); // Limit execution time to 5 minutes instead of unlimited
ini_set('memory_limit', '128M'); // Prevent memory exhaustion

// SECURITY: Rate limiting for playlist requests
session_start();
$clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$rateLimitKey = 'playlist_requests_' . hash('sha256', $clientIp);

if (!isset($_SESSION[$rateLimitKey])) {
    $_SESSION[$rateLimitKey] = ['count' => 0, 'last_request' => 0];
}

$now = time();
if ($now - $_SESSION[$rateLimitKey]['last_request'] < 60) {
    $_SESSION[$rateLimitKey]['count']++;
    if ($_SESSION[$rateLimitKey]['count'] > 10) {
        // Rate limit exceeded
        header($_SERVER['SERVER_PROTOCOL'] . ' 429 Too Many Requests');
        header('Retry-After: 60');
        error_log("SECURITY: Rate limit exceeded for playlist requests from IP: $clientIp");
        exit();
    }
} else {
    $_SESSION[$rateLimitKey] = ['count' => 1, 'last_request' => $now];
}

/**
 * SECURITY: Sanitize and validate input
 */
function sanitizeInput(string $input, int $maxLength = 255): string
{
    $input = trim($input);
    $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    return substr($input, 0, $maxLength);
}

/**
 * SECURITY: Validate username format
 */
function validateUsername(string $username): bool
{
    // Only allow alphanumeric characters, underscore, and dash
    return preg_match('/^[a-zA-Z0-9_-]{3,50}$/', $username) === 1;
}

/**
 * SECURITY: Validate password format
 */
function validatePassword(string $password): bool
{
    // Minimum security requirements
    return strlen($password) >= 6 && strlen($password) <= 255;
}

/**
 * SECURITY: Log authentication attempts
 */
function logAuthAttempt(string $username, string $ip, bool $success): void
{
    $logData = [
        'timestamp' => date('Y-m-d H:i:s'),
        'username' => substr($username, 0, 50),
        'ip' => $ip,
        'success' => $success,
        'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 255)
    ];
    
    $logDir = '/var/log/fos-streaming/';
    if (!is_dir($logDir)) {
        mkdir($logDir, 0750, true);
    }
    
    $logFile = $logDir . 'playlist_auth.log';
    if (is_writable($logDir)) {
        file_put_contents($logFile, json_encode($logData) . "\n", FILE_APPEND | LOCK_EX);
        chmod($logFile, 0640);
    }
}

/**
 * SECURITY: Generate secure URLs
 */
function generateSecureStreamUrl(string $webip, int $webport, string $username, string $password, int $streamId): string
{
    // Validate inputs
    if (!filter_var($webip, FILTER_VALIDATE_IP)) {
        throw new InvalidArgumentException('Invalid IP address');
    }
    
    if ($webport < 1024 || $webport > 65535) {
        throw new InvalidArgumentException('Invalid port number');
    }
    
    if (!validateUsername($username) || !validatePassword($password)) {
        throw new InvalidArgumentException('Invalid credentials format');
    }
    
    if ($streamId <= 0) {
        throw new InvalidArgumentException('Invalid stream ID');
    }
    
    // Use HTTPS if available, otherwise HTTP
    $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
    
    return sprintf(
        '%s://%s:%d/live/%s/%s/%d',
        $protocol,
        $webip,
        $webport,
        urlencode($username),
        urlencode($password),
        $streamId
    );
}

/**
 * SECURITY: Escape XML content
 */
function escapeXml(string $content): string
{
    return htmlspecialchars($content, ENT_XML1 | ENT_QUOTES, 'UTF-8');
}

// Get and validate user agent
$userAgent = sanitizeInput($_SERVER['HTTP_USER_AGENT'] ?? '');

// SECURITY: Validate required parameters
if (empty($_GET['username']) || empty($_GET['password'])) {
    header($_SERVER['SERVER_PROTOCOL'] . ' 401 Unauthorized');
    header('WWW-Authenticate: Basic realm="FOS-Streaming"');
    logAuthAttempt($_GET['username'] ?? 'empty', $clientIp, false);
    error_log("SECURITY: Missing credentials from IP: $clientIp");
    exit();
}

// SECURITY: Sanitize and validate credentials
$username = sanitizeInput($_GET['username'], 50);
$password = sanitizeInput($_GET['password'], 255);

if (!validateUsername($username) || !validatePassword($password)) {
    header($_SERVER['SERVER_PROTOCOL'] . ' 400 Bad Request');
    logAuthAttempt($username, $clientIp, false);
    error_log("SECURITY: Invalid credential format from IP: $clientIp, Username: $username");
    exit();
}

// SECURITY: Use prepared statements equivalent (secure query)
try {
    $user = User::where('username', '=', $username)
                ->where('password', '=', $password)
                ->where('active', '=', 1)
                ->first();
                
    if (!$user) {
        header($_SERVER['SERVER_PROTOCOL'] . ' 401 Unauthorized');
        logAuthAttempt($username, $clientIp, false);
        error_log("SECURITY: Failed authentication from IP: $clientIp, Username: $username");
        exit();
    }
    
    // Log successful authentication
    logAuthAttempt($username, $clientIp, true);
    
} catch (Exception $e) {
    header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error');
    error_log("SECURITY: Database error during authentication: " . $e->getMessage());
    exit();
}

// Get settings
try {
    $setting = Setting::first();
    if (!$setting) {
        throw new Exception('Settings not found');
    }
} catch (Exception $e) {
    header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error');
    error_log("SECURITY: Settings error: " . $e->getMessage());
    exit();
}

// SECURITY: Validate settings
if (!filter_var($setting->webip, FILTER_VALIDATE_IP)) {
    error_log("SECURITY: Invalid webip in settings: " . $setting->webip);
    header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error');
    exit();
}

if ($setting->webport < 1024 || $setting->webport > 65535) {
    error_log("SECURITY: Invalid webport in settings: " . $setting->webport);
    header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error');
    exit();
}

// Handle different playlist formats
try {
    
    // E2 Enigma2 format
    if (isset($_GET['e2'])) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="userbouquet.favourites.tv"');
        header('Cache-Control: no-cache, must-revalidate');
        header('Expires: 0');
        
        echo "#NAME FOS-Streaming\r\n";
        
        foreach ($user->categories as $category) {
            foreach ($category->streams as $stream) {
                if ($stream->running == 1) {
                    $streamUrl = generateSecureStreamUrl(
                        $setting->webip,
                        $setting->webport,
                        $username,
                        $password,
                        $stream->id
                    );
                    
                    $encodedUrl = str_replace([':', '/'], ['%3A', '%2F'], $streamUrl);
                    echo "#SERVICE 1:0:1:0:0:0:0:0:0:0:" . $encodedUrl . "\r\n";
                    echo "#DESCRIPTION " . escapeXml($stream->name) . "\r\n";
                }
            }
        }
        exit();
    }
    
    // M3U format
    if (isset($_GET['m3u'])) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="tv_user.m3u"');
        header('Cache-Control: no-cache, must-revalidate');
        header('Expires: 0');
        
        echo "#EXTM3U\r\n";
        
        foreach ($user->categories as $category) {
            foreach ($category->streams as $stream) {
                if ($stream->running == 1) {
                    $streamUrl = generateSecureStreamUrl(
                        $setting->webip,
                        $setting->webport,
                        $username,
                        $password,
                        $stream->id
                    );
                    
                    // SECURITY: Validate and sanitize logo URL
                    $logoUrl = '';
                    if (!empty($stream->logo)) {
                        if (strpos($userAgent, 'Kodi') !== false) {
                            // For Kodi, use the logo as-is but validate it
                            if (filter_var($stream->logo, FILTER_VALIDATE_URL)) {
                                $logoUrl = htmlspecialchars($stream->logo, ENT_QUOTES, 'UTF-8');
                            }
                        } else {
                            // Construct logo URL securely
                            $baseLogoUrl = filter_var($setting->logourl, FILTER_VALIDATE_URL);
                            $logoFile = basename($stream->logo);
                            if ($baseLogoUrl && preg_match('/^[a-zA-Z0-9._-]+\.(jpg|jpeg|png|gif|svg)$/i', $logoFile)) {
                                $logoUrl = $baseLogoUrl . $logoFile;
                            }
                        }
                    }
                    
                    // SECURITY: Sanitize stream name and TV ID
                    $streamName = htmlspecialchars($stream->name, ENT_QUOTES, 'UTF-8');
                    $tvId = htmlspecialchars($stream->tvid ?? '', ENT_QUOTES, 'UTF-8');
                    
                    if (strpos($userAgent, 'Kodi') !== false) {
                        echo "#EXTINF:0 tvg-logo=\"" . $logoUrl . "\" tvg-id=\"" . $tvId . "\",[COLOR green]" . $streamName . "[/COLOR]\r\n";
                    } else {
                        echo "#EXTINF:0 tvg-logo=\"" . $logoUrl . "\" tvg-id=\"" . $tvId . "\"," . $streamName . "\r\n";
                    }
                    echo $streamUrl . "\r\n";
                }
            }
        }
        exit();
    }
    
    // AllFrTVWindows XML format
    if (isset($_GET['allfrtvwindows'])) {
        header('Content-Type: text/xml; charset=utf-8');
        header('Content-Disposition: attachment; filename="allfrtvwindows.xml"');
        header('Cache-Control: no-cache, must-revalidate');
        header('Expires: 0');
        
        echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
        echo "<channels>\r\n";
        
        foreach ($user->categories as $category) {
            foreach ($category->streams as $stream) {
                if ($stream->running == 1) {
                    $streamUrl = generateSecureStreamUrl(
                        $setting->webip,
                        $setting->webport,
                        $username,
                        $password,
                        $stream->id
                    );
                    
                    echo "  <channel>\r\n";
                    echo "    <name>" . escapeXml($stream->name) . "</name>\r\n";
                    echo "    <HQ>" . escapeXml($streamUrl) . "</HQ>\r\n";
                    echo "    <typeHQ>hls</typeHQ>\r\n";
                    echo "    <recordableHQ>true</recordableHQ>\r\n";
                    echo "    <category>IPTV</category>\r\n";
                    echo "  </channel>\r\n";
                }
            }
        }
        
        echo "</channels>\r\n";
        exit();
    }
    
    // If no specific format requested, return 400 Bad Request
    header($_SERVER['SERVER_PROTOCOL'] . ' 400 Bad Request');
    error_log("SECURITY: No valid playlist format requested from IP: $clientIp, Username: $username");
    echo "Bad Request: Please specify a valid playlist format (e2, m3u, or allfrtvwindows)";
    
} catch (Exception $e) {
    header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error');
    error_log("SECURITY: Playlist generation error: " . $e->getMessage() . " | IP: $clientIp | Username: $username");
    echo "Internal Server Error";
} catch (Error $e) {
    header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error');
    error_log("SECURITY: Fatal error in playlist generation: " . $e->getMessage() . " | IP: $clientIp | Username: $username");
    echo "Internal Server Error";
}

// Clean exit
exit();
?>

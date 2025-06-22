<?php
declare(strict_types=1);

/**
 * FOS-Streaming Secure Stream Handler
 * PHP 8.1+ compatible with comprehensive security enhancements
 */

// Security constants
define('MAX_STREAM_DURATION', 28800); // 8 hours max
define('MAX_CONNECTIONS_PER_IP', 10);
define('STREAM_TIMEOUT', 30);
define('MAX_FAILED_ATTEMPTS', 5);
define('RATE_LIMIT_WINDOW', 300); // 5 minutes

// Initialize error handling and limits
error_reporting(E_ERROR | E_WARNING); // Reduce verbosity in production
set_time_limit(MAX_STREAM_DURATION);
ini_set('memory_limit', '128M');

require_once 'config.php';

// Global variables for cleanup
$user_activity_id = 0;
$stream_handle = null;
$is_authenticated = false;

/**
 * Secure cleanup function
 */
function secureCleanup(): void
{
    global $user_activity_id, $stream_handle;
    
    try {
        if ($user_activity_id > 0) {
            $active = Activity::find($user_activity_id);
            if ($active) {
                $active->date_end = date('Y-m-d H:i:s');
                $active->save();
            }
        }
        
        if ($stream_handle) {
            fclose($stream_handle);
        }
        
        // Log stream end
        logStreamEvent('stream_ended', [
            'activity_id' => $user_activity_id,
            'duration' => time() - ($_SESSION['stream_start'] ?? time())
        ]);
        
    } catch (Exception $e) {
        error_log('Cleanup error: ' . $e->getMessage());
    }
    
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }
    exit(0);
}

/**
 * Security logging function
 */
function logStreamEvent(string $event, array $context = []): void
{
    $logData = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event' => $event,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'context' => $context
    ];
    
    $logFile = '/var/log/fos-streaming/stream.log';
    if (is_writable(dirname($logFile))) {
        file_put_contents($logFile, json_encode($logData) . "\n", FILE_APPEND | LOCK_EX);
    }
}

/**
 * Rate limiting for stream access
 */
function checkStreamRateLimit(string $ip): bool
{
    $cacheFile = sys_get_temp_dir() . '/fos_stream_rate_' . md5($ip);
    
    if (file_exists($cacheFile)) {
        $data = json_decode(file_get_contents($cacheFile), true);
        
        if ($data && isset($data['attempts'], $data['timestamp'])) {
            // Reset counter after time window
            if (time() - $data['timestamp'] > RATE_LIMIT_WINDOW) {
                unlink($cacheFile);
                return true;
            }
            
            // Check if rate limit exceeded
            if ($data['attempts'] >= MAX_FAILED_ATTEMPTS) {
                return false;
            }
        }
    }
    
    return true;
}

/**
 * Record failed stream attempt
 */
function recordStreamFailure(string $ip): void
{
    $cacheFile = sys_get_temp_dir() . '/fos_stream_rate_' . md5($ip);
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

/**
 * Validate stream parameters
 */
function validateStreamParams(array $params): array
{
    $errors = [];
    
    // Validate username
    if (empty($params['username'])) {
        $errors[] = 'Username required';
    } elseif (!preg_match('/^[a-zA-Z0-9_-]{1,50}$/', $params['username'])) {
        $errors[] = 'Invalid username format';
    }
    
    // Validate password
    if (empty($params['password'])) {
        $errors[] = 'Password required';
    } elseif (strlen($params['password']) > 100) {
        $errors[] = 'Password too long';
    }
    
    // Validate stream ID
    if (empty($params['stream'])) {
        $errors[] = 'Stream ID required';
    } elseif (!is_numeric($params['stream']) || (int)$params['stream'] <= 0) {
        $errors[] = 'Invalid stream ID';
    }
    
    return $errors;
}

/**
 * Check if user agent is blocked
 */
function isUserAgentBlocked(string $userAgent): bool
{
    if (empty($userAgent) || $userAgent === '0') {
        return true; // Block empty user agents
    }
    
    try {
        return BlockedUseragent::where('name', $userAgent)->exists();
    } catch (Exception $e) {
        error_log('Error checking blocked user agent: ' . $e->getMessage());
        return false;
    }
}

/**
 * Check if IP is blocked
 */
function isIpBlocked(string $ip): bool
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return true; // Block invalid IPs
    }
    
    try {
        return BlockedIp::where('ip', $ip)->exists();
    } catch (Exception $e) {
        error_log('Error checking blocked IP: ' . $e->getMessage());
        return false;
    }
}

/**
 * Authenticate user securely
 */
function authenticateUser(string $username, string $password): ?object
{
    try {
        // Use secure password verification
        $user = User::where('username', $username)
                   ->where('active', 1)
                   ->first();
        
        if ($user && password_verify($password, $user->password)) {
            // Check expiration date
            if ($user->exp_date !== '0000-00-00' && $user->exp_date <= date('Y-m-d H:i:s')) {
                logStreamEvent('expired_user_attempt', ['username' => $username]);
                return null;
            }
            
            return $user;
        }
        
        return null;
        
    } catch (Exception $e) {
        error_log('Authentication error: ' . $e->getMessage());
        return null;
    }
}

/**
 * Check connection limits
 */
function checkConnectionLimits(object $user, string $userIp): bool
{
    try {
        if ($user->max_connections == 0) {
            return true; // Unlimited connections
        }
        
        $activeConnections = Activity::where('user_id', $user->id)
                                   ->whereNull('date_end')
                                   ->count();
        
        // Allow reconnection from same IP
        $sameIpConnection = Activity::where('user_id', $user->id)
                                  ->where('user_ip', $userIp)
                                  ->whereNull('date_end')
                                  ->first();
        
        if ($sameIpConnection) {
            $activeConnections--;
        }
        
        return $activeConnections < $user->max_connections;
        
    } catch (Exception $e) {
        error_log('Connection limit check error: ' . $e->getMessage());
        return false;
    }
}

/**
 * Get stream URL safely
 */
function getStreamUrl(object $stream): ?string
{
    $url = match($stream->checker) {
        2 => $stream->streamurl2,
        3 => $stream->streamurl3,
        default => $stream->streamurl
    };
    
    // Validate URL
    if (empty($url)) {
        return null;
    }
    
    // Basic URL validation
    if (!filter_var($url, FILTER_VALIDATE_URL) && 
        !preg_match('/^[a-zA-Z][a-zA-Z0-9+.-]*:/', $url)) {
        return null;
    }
    
    return $url;
}

/**
 * Stream HLS content securely
 */
function streamHlsContent(object $stream, object $setting): void
{
    global $user_activity_id;
    
    $hlsFolder = $setting->hlsfolder;
    
    // Validate HLS folder
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $hlsFolder)) {
        logStreamEvent('invalid_hls_folder', ['folder' => $hlsFolder]);
        http_response_code(500);
        exit();
    }
    
    $folderPath = '/home/fos-streaming/fos/www/' . $hlsFolder . '/';
    $playlistFile = $folderPath . $stream->id . '_.m3u8';
    
    // Validate paths are within allowed directory
    $realFolderPath = realpath($folderPath);
    $allowedBasePath = realpath('/home/fos-streaming/fos/www/');
    
    if (!$realFolderPath || strpos($realFolderPath, $allowedBasePath) !== 0) {
        logStreamEvent('path_traversal_attempt', ['folder' => $folderPath]);
        http_response_code(403);
        exit();
    }
    
    if (!file_exists($playlistFile)) {
        logStreamEvent('playlist_not_found', ['file' => $playlistFile]);
        http_response_code(404);
        exit();
    }
    
    // Read playlist safely
    $playlistContent = file_get_contents($playlistFile);
    if ($playlistContent === false) {
        http_response_code(500);
        exit();
    }
    
    // Extract segment files
    if (!preg_match_all('/([^\/\s]+\.ts)/', $playlistContent, $matches)) {
        http_response_code(404);
        exit();
    }
    
    $segmentFiles = $matches[1];
    
    // Validate and stream segments
    foreach ($segmentFiles as $segmentFile) {
        $segmentPath = $folderPath . $segmentFile;
        
        // Security: validate filename
        if (!preg_match('/^' . preg_quote((string)$stream->id, '/') . '_\d+\.ts$/', $segmentFile)) {
            logStreamEvent('invalid_segment_filename', ['file' => $segmentFile]);
            continue;
        }
        
        $realSegmentPath = realpath($segmentPath);
        if (!$realSegmentPath || strpos($realSegmentPath, $realFolderPath) !== 0) {
            logStreamEvent('segment_path_traversal', ['file' => $segmentPath]);
            continue;
        }
        
        if (!file_exists($segmentPath)) {
            logStreamEvent('segment_not_found', ['file' => $segmentPath]);
            break;
        }
        
        // Stream segment content
        $segmentHandle = fopen($segmentPath, 'rb');
        if ($segmentHandle === false) {
            continue;
        }
        
        while (!feof($segmentHandle)) {
            $chunk = fread($segmentHandle, 8192);
            if ($chunk === false) {
                break;
            }
            echo $chunk;
            
            // Check if connection is still alive
            if (connection_aborted()) {
                fclose($segmentHandle);
                logStreamEvent('connection_aborted', ['activity_id' => $user_activity_id]);
                exit();
            }
        }
        
        fclose($segmentHandle);
    }
    
    // Continue with live segments
    if (!empty($segmentFiles)) {
        $lastSegment = end($segmentFiles);
        if (preg_match('/_(\d+)\.ts$/', $lastSegment, $matches)) {
            $segmentNumber = (int)$matches[1];
            streamLiveSegments($stream, $setting, $folderPath, $segmentNumber + 1);
        }
    }
}

/**
 * Stream live segments
 */
function streamLiveSegments(object $stream, object $setting, string $folderPath, int $startSegment): void
{
    global $user_activity_id;
    
    $maxWaitTime = 16;
    $segmentNumber = $startSegment;
    $streamStartTime = time();
    
    while ((time() - $streamStartTime) < MAX_STREAM_DURATION) {
        $currentSegment = sprintf('%d_%d.ts', $stream->id, $segmentNumber);
        $nextSegment = sprintf('%d_%d.ts', $stream->id, $segmentNumber + 1);
        $currentPath = $folderPath . $currentSegment;
        $nextPath = $folderPath . $nextSegment;
        
        $waitTime = 0;
        
        // Wait for current segment
        while ($waitTime < $maxWaitTime && !file_exists($currentPath)) {
            if (connection_aborted()) {
                logStreamEvent('connection_aborted_waiting', ['activity_id' => $user_activity_id]);
                exit();
            }
            
            sleep(1);
            $waitTime++;
        }
        
        if (!file_exists($currentPath)) {
            logStreamEvent('segment_timeout', [
                'segment' => $currentSegment,
                'wait_time' => $waitTime
            ]);
            break;
        }
        
        // Stream current segment
        $segmentHandle = fopen($currentPath, 'rb');
        if ($segmentHandle === false) {
            $segmentNumber++;
            continue;
        }
        
        while (!feof($segmentHandle)) {
            $chunk = fread($segmentHandle, 8192);
            if ($chunk === false) {
                break;
            }
            echo $chunk;
            
            if (connection_aborted()) {
                fclose($segmentHandle);
                exit();
            }
            
            // Slow down if next segment isn't ready
            if (!file_exists($nextPath)) {
                usleep(100000); // 0.1 second
            }
        }
        
        fclose($segmentHandle);
        $segmentNumber++;
    }
}

// Register secure cleanup function
register_shutdown_function('secureCleanup');

// Set secure headers
header('Content-Type: video/mp2t');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');

// Get client information
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Security validations
if (empty($clientIp) || !filter_var($clientIp, FILTER_VALIDATE_IP)) {
    logStreamEvent('invalid_client_ip', ['ip' => $clientIp]);
    http_response_code(400);
    exit();
}

// Check rate limiting
if (!checkStreamRateLimit($clientIp)) {
    logStreamEvent('rate_limit_exceeded', ['ip' => $clientIp]);
    http_response_code(429);
    exit();
}

// Check if IP is blocked
if (isIpBlocked($clientIp)) {
    logStreamEvent('blocked_ip_attempt', ['ip' => $clientIp]);
    recordStreamFailure($clientIp);
    http_response_code(403);
    exit();
}

// Check if user agent is blocked
if (isUserAgentBlocked($userAgent)) {
    logStreamEvent('blocked_user_agent', ['user_agent' => $userAgent, 'ip' => $clientIp]);
    recordStreamFailure($clientIp);
    http_response_code(403);
    exit();
}

// Validate required parameters
$requiredParams = ['username', 'password', 'stream'];
foreach ($requiredParams as $param) {
    if (!isset($_GET[$param])) {
        logStreamEvent('missing_parameter', ['param' => $param, 'ip' => $clientIp]);
        recordStreamFailure($clientIp);
        http_response_code(400);
        exit();
    }
}

// Validate stream parameters
$validationErrors = validateStreamParams($_GET);
if (!empty($validationErrors)) {
    logStreamEvent('parameter_validation_failed', [
        'errors' => $validationErrors,
        'ip' => $clientIp
    ]);
    recordStreamFailure($clientIp);
    http_response_code(400);
    exit();
}

$username = $_GET['username'];
$password = $_GET['password'];
$streamId = (int)$_GET['stream'];

// Authenticate user
$user = authenticateUser($username, $password);
if (!$user) {
    logStreamEvent('authentication_failed', [
        'username' => $username,
        'ip' => $clientIp,
        'user_agent' => $userAgent
    ]);
    recordStreamFailure($clientIp);
    
    // Log to separate failed login file for compatibility
    $logEntry = sprintf(
        "Warning --> IP: [%s] - %s - Failed Login - User: %s\n",
        $clientIp,
        date("d-m-Y H:i:s"),
        $username
    );
    
    $logFile = '/var/log/fos-streaming/failed-logins.log';
    if (is_writable(dirname($logFile))) {
        file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    }
    
    sleep(3); // Prevent brute force
    http_response_code(401);
    exit();
}

$is_authenticated = true;

// Check connection limits
if (!checkConnectionLimits($user, $clientIp)) {
    logStreamEvent('connection_limit_exceeded', [
        'user_id' => $user->id,
        'max_connections' => $user->max_connections,
        'ip' => $clientIp
    ]);
    http_response_code(429);
    exit();
}

// Get stream
try {
    $stream = Stream::find($streamId);
    if (!$stream) {
        logStreamEvent('stream_not_found', ['stream_id' => $streamId]);
        http_response_code(404);
        exit();
    }
} catch (Exception $e) {
    logStreamEvent('stream_lookup_error', ['error' => $e->getMessage()]);
    http_response_code(500);
    exit();
}

// Create activity record
try {
    $activity = new Activity();
    $activity->user_id = $user->id;
    $activity->stream_id = $stream->id;
    $activity->user_agent = $userAgent;
    $activity->user_ip = $clientIp;
    $activity->pid = getmypid();
    $activity->bandwidth = 0;
    $activity->date_start = date('Y-m-d H:i:s');
    $activity->save();
    
    $user_activity_id = $activity->id;
    $_SESSION['stream_start'] = time();
    
    // Update user information
    $user->lastconnected_ip = $clientIp;
    $user->last_stream = $stream->id;
    $user->useragent = $userAgent;
    $user->save();
    
    logStreamEvent('stream_started', [
        'user_id' => $user->id,
        'stream_id' => $stream->id,
        'activity_id' => $user_activity_id
    ]);
    
} catch (Exception $e) {
    logStreamEvent('activity_creation_error', ['error' => $e->getMessage()]);
    http_response_code(500);
    exit();
}

// Get settings
try {
    $setting = Setting::first();
    if (!$setting) {
        logStreamEvent('settings_not_found');
        http_response_code(500);
        exit();
    }
} catch (Exception $e) {
    logStreamEvent('settings_error', ['error' => $e->getMessage()]);
    http_response_code(500);
    exit();
}

// Start streaming
try {
    streamHlsContent($stream, $setting);
} catch (Exception $e) {
    logStreamEvent('streaming_error', [
        'error' => $e->getMessage(),
        'activity_id' => $user_activity_id
    ]);
    http_response_code(500);
    exit();
}

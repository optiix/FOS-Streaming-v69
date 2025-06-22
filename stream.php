<?php

/**
 * FOS-Streaming stream.php
 * BACKWARD COMPATIBLE - Original streaming logic with security enhancements
 * Maintains exact same streaming behavior while adding protection
 */

// ORIGINAL: Set execution limits and headers
set_time_limit(28800); // 8 hours
ini_set('memory_limit', '128M');
error_reporting(E_ERROR | E_WARNING);

require_once 'config.php';

// ORIGINAL: Set streaming headers exactly as before
header('Content-Type: video/mp2t');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');
header('Access-Control-Allow-Origin: *');

// Enhanced but compatible logging
function streamLog($message, $context = [])
{
    $logData = [
        'timestamp' => date('Y-m-d H:i:s'),
        'message' => $message,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'context' => $context
    ];
    
    // Try to log but don't break streaming if it fails
    $logFile = '/var/log/fos-streaming/stream.log';
    if (is_dir(dirname($logFile)) && is_writable(dirname($logFile))) {
        file_put_contents($logFile, json_encode($logData) . "\n", FILE_APPEND | LOCK_EX);
    }
}

// Enhanced cleanup function (compatible with original)
function cleanupStream()
{
    global $user_activity_id, $stream_id;
    
    try {
        if (!empty($user_activity_id)) {
            $active = Activity::find($user_activity_id);
            if ($active) {
                $active->date_end = date('Y-m-d H:i:s');
                $active->save();
            }
        }
        
        streamLog("Stream ended", [
            'activity_id' => $user_activity_id ?? 0,
            'stream_id' => $stream_id ?? 0
        ]);
        
    } catch (Exception $e) {
        error_log('Stream cleanup error: ' . $e->getMessage());
    }
    
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }
    exit(0);
}

// Register cleanup function
register_shutdown_function('cleanupStream');

// Initialize variables for cleanup
$user_activity_id = 0;
$stream_id = 0;

// ORIGINAL: Get parameters from URL
$username = isset($_GET['username']) ? $_GET['username'] : '';
$password = isset($_GET['password']) ? $_GET['password'] : '';
$stream_id = isset($_GET['stream']) ? (int)$_GET['stream'] : 0;

// Enhanced input validation (but maintain original behavior)
if (empty($username) || empty($password) || $stream_id <= 0) {
    streamLog("Missing parameters", [
        'username' => $username,
        'stream_id' => $stream_id,
        'has_password' => !empty($password)
    ]);
    http_response_code(400);
    exit();
}

// Basic input sanitization (enhance but don't break)
$username = strip_tags($username);
if (strlen($username) > 50) {
    streamLog("Username too long", ['username' => $username]);
    http_response_code(400);
    exit();
}

if (strlen($password) > 100) {
    streamLog("Password too long");
    http_response_code(400);
    exit();
}

// Enhanced IP validation
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
if (empty($clientIp) || !filter_var($clientIp, FILTER_VALIDATE_IP)) {
    streamLog("Invalid client IP", ['ip' => $clientIp]);
    http_response_code(400);
    exit();
}

// Enhanced user agent checking (optional, compatible)
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Optional: Check blocked IPs (if function exists)
try {
    if (class_exists('BlockedIp')) {
        $blockedIp = BlockedIp::where('ip', $clientIp)->first();
        if ($blockedIp) {
            streamLog("Blocked IP attempted access", ['ip' => $clientIp]);
            http_response_code(403);
            exit();
        }
    }
} catch (Exception $e) {
    // Silent fail - don't break streaming if DB error
    error_log('BlockedIp check error: ' . $e->getMessage());
}

// Optional: Check blocked user agents (if function exists)
try {
    if (class_exists('BlockedUseragent') && !empty($userAgent)) {
        $blockedAgent = BlockedUseragent::where('name', $userAgent)->first();
        if ($blockedAgent) {
            streamLog("Blocked user agent attempted access", [
                'user_agent' => $userAgent,
                'ip' => $clientIp
            ]);
            http_response_code(403);
            exit();
        }
    }
} catch (Exception $e) {
    // Silent fail - don't break streaming
    error_log('BlockedUseragent check error: ' . $e->getMessage());
}

// COMPATIBILITY: Support both old MD5 and new secure authentication
$user = null;
$authMethod = 'unknown';

try {
    // Method 1: ORIGINAL MD5 authentication (for existing user URLs)
    $userCount = User::where('username', '=', $username)
                    ->where('password', '=', md5($password))
                    ->where('active', '=', 1)
                    ->count();
    
    if ($userCount > 0) {
        $user = User::where('username', '=', $username)
                   ->where('password', '=', md5($password))
                   ->where('active', '=', 1)
                   ->first();
        $authMethod = 'md5_legacy';
        
        // Optional: Automatic password migration during streaming
        try {
            if ($user) {
                $user->password = password_hash($password, PASSWORD_DEFAULT);
                $user->save();
                $authMethod = 'md5_migrated';
            }
        } catch (Exception $e) {
            // Migration failed, but streaming continues
            error_log("Password migration failed during streaming for $username: " . $e->getMessage());
        }
    } else {
        // Method 2: New secure password authentication (for migrated users)
        $user = User::where('username', '=', $username)
                   ->where('active', '=', 1)
                   ->first();
        
        if ($user && strlen($user->password) > 32) {
            // This looks like a secure hash
            if (password_verify($password, $user->password)) {
                $authMethod = 'secure_password';
            } else {
                $user = null; // Authentication failed
            }
        } else {
            $user = null; // No user found or invalid password format
        }
    }
    
} catch (Exception $e) {
    streamLog("Database authentication error", ['error' => $e->getMessage()]);
    $user = null;
}

// ORIGINAL: Check if authentication failed
if (!$user) {
    streamLog("Authentication failed", [
        'username' => $username,
        'ip' => $clientIp,
        'user_agent' => $userAgent
    ]);
    
    // ORIGINAL: Log failed login (compatible with existing log format)
    $logEntry = sprintf(
        "Warning --> IP: [%s] - %s - Failed Login - User: %s\n",
        $clientIp,
        date("d-m-Y H:i:s"),
        $username
    );
    
    $logFile = '/home/fos-streaming/fos/www/log/Failed-Login-Attempts';
    if (is_dir(dirname($logFile))) {
        file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    }
    
    sleep(3); // Prevent brute force
    http_response_code(401);
    exit();
}

// ORIGINAL: Check user expiration
if ($user->exp_date != '0000-00-00' && $user->exp_date <= date('Y-m-d H:i:s')) {
    streamLog("Expired user attempted access", [
        'username' => $username,
        'exp_date' => $user->exp_date
    ]);
    http_response_code(401);
    exit();
}

// ORIGINAL: Check connection limits
$activeConnections = Activity::where('user_id', $user->id)
                           ->whereNull('date_end')
                           ->count();

if ($user->max_connections > 0 && $activeConnections >= $user->max_connections) {
    // ORIGINAL: Allow reconnection from same IP
    $sameIpConnection = Activity::where('user_id', $user->id)
                              ->where('user_ip', $clientIp)
                              ->whereNull('date_end')
                              ->first();
    
    if (!$sameIpConnection) {
        streamLog("Connection limit exceeded", [
            'username' => $username,
            'max_connections' => $user->max_connections,
            'active_connections' => $activeConnections
        ]);
        http_response_code(429);
        exit();
    }
}

// ORIGINAL: Get stream information
try {
    $stream = Stream::find($stream_id);
    if (!$stream) {
        streamLog("Stream not found", ['stream_id' => $stream_id]);
        http_response_code(404);
        exit();
    }
} catch (Exception $e) {
    streamLog("Stream lookup error", ['error' => $e->getMessage()]);
    http_response_code(500);
    exit();
}

// ORIGINAL: Create activity record
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
    
    // ORIGINAL: Update user information
    $user->lastconnected_ip = $clientIp;
    $user->last_stream = $stream->id;
    $user->useragent = $userAgent;
    $user->save();
    
    streamLog("Stream started", [
        'user_id' => $user->id,
        'username' => $username,
        'stream_id' => $stream->id,
        'activity_id' => $user_activity_id,
        'auth_method' => $authMethod
    ]);
    
} catch (Exception $e) {
    streamLog("Activity creation error", ['error' => $e->getMessage()]);
    http_response_code(500);
    exit();
}

// ORIGINAL: Get settings
try {
    $setting = Setting::first();
    if (!$setting) {
        streamLog("Settings not found");
        http_response_code(500);
        exit();
    }
} catch (Exception $e) {
    streamLog("Settings error", ['error' => $e->getMessage()]);
    http_response_code(500);
    exit();
}

// ORIGINAL: Start streaming process - EXACT same logic as original
$hlsFolder = $setting->hlsfolder;

// Enhanced path validation but maintain original behavior
if (empty($hlsFolder)) {
    streamLog("HLS folder not configured");
    http_response_code(500);
    exit();
}

// Basic security check for HLS folder
$hlsFolder = preg_replace('/[^a-zA-Z0-9_-]/', '', $hlsFolder);
if (empty($hlsFolder)) {
    streamLog("Invalid HLS folder configuration");
    http_response_code(500);
    exit();
}

$folderPath = '/home/fos-streaming/fos/www/' . $hlsFolder . '/';
$playlistFile = $folderPath . $stream->id . '_.m3u8';

// ORIGINAL: Check if playlist exists
if (!file_exists($playlistFile)) {
    streamLog("Playlist file not found", ['file' => $playlistFile]);
    http_response_code(404);
    exit();
}

// ORIGINAL: Read playlist content
$playlistContent = file_get_contents($playlistFile);
if ($playlistContent === false) {
    streamLog("Failed to read playlist file", ['file' => $playlistFile]);
    http_response_code(500);
    exit();
}

// ORIGINAL: Extract segment files from playlist
if (!preg_match_all('/([^\/\s]+\.ts)/', $playlistContent, $matches)) {
    streamLog("No segments found in playlist");
    http_response_code(404);
    exit();
}

$segmentFiles = $matches[1];
streamLog("Found segments", ['count' => count($segmentFiles)]);

// ORIGINAL: Stream existing segments
foreach ($segmentFiles as $segmentFile) {
    $segmentPath = $folderPath . $segmentFile;
    
    // Enhanced security: validate segment filename
    if (!preg_match('/^' . preg_quote((string)$stream->id, '/') . '_\d+\.ts$/', $segmentFile)) {
        streamLog("Invalid segment filename", ['file' => $segmentFile]);
        continue;
    }
    
    if (!file_exists($segmentPath)) {
        streamLog("Segment file not found", ['file' => $segmentPath]);
        break;
    }
    
    // ORIGINAL: Stream segment content
    $segmentHandle = fopen($segmentPath, 'rb');
    if ($segmentHandle === false) {
        streamLog("Failed to open segment", ['file' => $segmentPath]);
        continue;
    }
    
    while (!feof($segmentHandle)) {
        $chunk = fread($segmentHandle, 8192);
        if ($chunk === false) {
            break;
        }
        echo $chunk;
        
        // ORIGINAL: Check if client disconnected
        if (connection_aborted()) {
            fclose($segmentHandle);
            streamLog("Client disconnected during segment streaming");
            exit();
        }
    }
    
    fclose($segmentHandle);
}

// ORIGINAL: Continue with live segments
if (!empty($segmentFiles)) {
    $lastSegment = end($segmentFiles);
    if (preg_match('/_(\d+)\.ts$/', $lastSegment, $matches)) {
        $segmentNumber = (int)$matches[1] + 1;
        
        // ORIGINAL: Stream live segments
        $maxWaitTime = 16;
        $startTime = time();
        
        while ((time() - $startTime) < 28800) { // 8 hours max
            $currentSegment = sprintf('%d_%d.ts', $stream->id, $segmentNumber);
            $nextSegment = sprintf('%d_%d.ts', $stream->id, $segmentNumber + 1);
            $currentPath = $folderPath . $currentSegment;
            $nextPath = $folderPath . $nextSegment;
            
            $waitTime = 0;
            
            // ORIGINAL: Wait for current segment
            while ($waitTime < $maxWaitTime && !file_exists($currentPath)) {
                if (connection_aborted()) {
                    streamLog("Client disconnected while waiting for segment");
                    exit();
                }
                
                sleep(1);
                $waitTime++;
            }
            
            if (!file_exists($currentPath)) {
                streamLog("Segment timeout", [
                    'segment' => $currentSegment,
                    'wait_time' => $waitTime
                ]);
                break;
            }
            
            // ORIGINAL: Stream current segment
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
                    streamLog("Client disconnected during live streaming");
                    exit();
                }
                
                // ORIGINAL: Slow down if next segment isn't ready
                if (!file_exists($nextPath)) {
                    usleep(100000); // 0.1 second
                }
            }
            
            fclose($segmentHandle);
            $segmentNumber++;
        }
    }
}

streamLog("Stream ended normally");

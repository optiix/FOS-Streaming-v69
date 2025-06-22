<?php
declare(strict_types=1);

/**
 * FOS-Streaming Stream Handler
 * PHP 8.1 compatible with essential security only
 */

require_once 'config.php';

// Basic security settings
set_time_limit(0);
error_reporting(0);

// Simple cleanup function
function cleanup(): void
{
    global $user_activity_id;
    
    if (!empty($user_activity_id)) {
        try {
            $active = Activity::find($user_activity_id);
            if ($active) {
                $active->date_end = date('Y-m-d H:i:s');
                $active->save();
            }
        } catch (Exception $e) {
            // Silent fail for compatibility
        }
    }
    
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }
}

// Basic input validation
function validateInput(string $input, int $maxLength = 100): string
{
    return substr(htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8'), 0, $maxLength);
}

// Check if IP is blocked (simple version)
function isIpBlocked(string $ip): bool
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return true;
    }
    
    try {
        // Only check if BlockedIp model exists and has records
        if (class_exists('BlockedIp')) {
            return BlockedIp::where('ip_address', $ip)->exists();
        }
    } catch (Exception $e) {
        // If there's an error, don't block - for compatibility
    }
    
    return false;
}

// Register cleanup
register_shutdown_function('cleanup');

// Set headers
header('Content-Type: video/mp2t');
header('Cache-Control: no-cache');

// Get client info
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Basic security checks
if (empty($clientIp) || !filter_var($clientIp, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    exit();
}

// Check if IP is blocked
if (isIpBlocked($clientIp)) {
    http_response_code(403);
    exit();
}

// Check required parameters
if (empty($_GET['username']) || empty($_GET['password']) || empty($_GET['stream'])) {
    http_response_code(400);
    exit();
}

// Validate and sanitize inputs
$username = validateInput($_GET['username'], 50);
$password = validateInput($_GET['password'], 100);
$streamId = (int)$_GET['stream'];

if (empty($username) || empty($password) || $streamId <= 0) {
    http_response_code(400);
    exit();
}

// Authenticate user (keeping your existing logic)
try {
    $user = User::where('username', '=', $username)
                ->where('password', '=', $password)
                ->where('active', '=', 1)
                ->first();
                
    if (!$user) {
        // Log failed attempt (simple version)
        $logEntry = sprintf(
            "Warning --> IP: [%s] - %s - Failed Login - User: %s\n",
            $clientIp,
            date("d-m-Y H:i:s"),
            $username
        );
        
        if (is_writable('/var/log/')) {
            file_put_contents('/var/log/fos-streaming-failed.log', $logEntry, FILE_APPEND | LOCK_EX);
        }
        
        http_response_code(401);
        exit();
    }
    
    // Check expiration
    if ($user->exp_date !== '0000-00-00' && $user->exp_date <= date('Y-m-d H:i:s')) {
        http_response_code(401);
        exit();
    }
    
} catch (Exception $e) {
    http_response_code(500);
    exit();
}

// Check connection limits (simplified)
try {
    if ($user->max_connections > 0) {
        $activeConnections = Activity::where('user_id', $user->id)
                                   ->whereNull('date_end')
                                   ->count();
                                   
        if ($activeConnections >= $user->max_connections) {
            http_response_code(429);
            exit();
        }
    }
} catch (Exception $e) {
    // Continue if there's an error checking limits
}

// Get stream
try {
    $stream = Stream::find($streamId);
    if (!$stream) {
        http_response_code(404);
        exit();
    }
} catch (Exception $e) {
    http_response_code(500);
    exit();
}

// Create activity record
$user_activity_id = 0;
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
    
    // Update user info
    $user->lastconnected_ip = $clientIp;
    $user->last_stream = $stream->id;
    $user->useragent = $userAgent;
    $user->save();
    
} catch (Exception $e) {
    // Continue even if activity creation fails
}

// Get settings
try {
    $setting = Setting::first();
    if (!$setting) {
        http_response_code(500);
        exit();
    }
} catch (Exception $e) {
    http_response_code(500);
    exit();
}

// Stream the content (simplified HLS streaming)
try {
    $hlsFolder = $setting->hlsfolder ?? 'hls';
    
    // Basic path validation
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $hlsFolder)) {
        http_response_code(500);
        exit();
    }
    
    $folderPath = '/home/fos-streaming/fos/www/' . $hlsFolder . '/';
    $playlistFile = $folderPath . $stream->id . '_.m3u8';
    
    // Check if files exist and are readable
    if (!file_exists($playlistFile) || !is_readable($playlistFile)) {
        http_response_code(404);
        exit();
    }
    
    // Simple streaming loop
    $maxDuration = 28800; // 8 hours
    $startTime = time();
    $segmentNumber = 0;
    
    while ((time() - $startTime) < $maxDuration) {
        $segmentFile = sprintf('%s%d_%d.ts', $folderPath, $stream->id, $segmentNumber);
        
        // Wait for segment to exist
        $waitTime = 0;
        while ($waitTime < 30 && !file_exists($segmentFile)) {
            if (connection_aborted()) {
                exit();
            }
            sleep(1);
            $waitTime++;
        }
        
        if (!file_exists($segmentFile)) {
            break;
        }
        
        // Stream the segment
        $handle = fopen($segmentFile, 'rb');
        if ($handle) {
            while (!feof($handle)) {
                $chunk = fread($handle, 8192);
                if ($chunk === false) {
                    break;
                }
                echo $chunk;
                
                if (connection_aborted()) {
                    fclose($handle);
                    exit();
                }
            }
            fclose($handle);
        }
        
        $segmentNumber++;
    }
    
} catch (Exception $e) {
    http_response_code(500);
    exit();
}
?>

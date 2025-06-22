<?php
declare(strict_types=1);

/**
 * FOS-Streaming Secure Settings Page
 * FULLY BACKWARD COMPATIBLE with existing system
 * PHP 8.1+ compatible with security enhancements
 * SECURITY HARDENED VERSION
 */

// Include config with backward compatibility
require_once 'config.php';

// COMPATIBILITY: Ensure old logincheck() function works
logincheck();

// Initialize variables for backward compatibility
$message = [];
$setting = Setting::first();

// COMPATIBILITY: Handle both old and new authentication systems
if (!$setting) {
    // Fallback for database issues
    header("Location: index.php");
    exit();
}

/**
 * SECURITY: Sanitize input data
 */
function sanitizeInput(string $input, string $type = 'string'): string
{
    $input = trim($input);
    
    switch ($type) {
        case 'path':
            // Remove dangerous characters for file paths
            $input = preg_replace('/[^a-zA-Z0-9\/_.-]/', '', $input);
            break;
        case 'ip':
            // Keep only valid IP characters
            $input = preg_replace('/[^0-9.]/', '', $input);
            break;
        case 'url':
            // Basic URL sanitization
            $input = filter_var($input, FILTER_SANITIZE_URL);
            break;
        case 'alphanumeric':
            // Only letters, numbers, underscore, dash
            $input = preg_replace('/[^a-zA-Z0-9_-]/', '', $input);
            break;
        default:
            // General string sanitization
            $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }
    
    return $input;
}

/**
 * SECURITY: Enhanced input validation
 */
function validateSettingsInput(array $input): array
{
    $errors = [];
    
    // Validate FFmpeg path
    if (!empty($input['ffmpeg_path'])) {
        $ffmpegPath = sanitizeInput($input['ffmpeg_path'], 'path');
        
        // SECURITY: Restrict to allowed directories
        $allowedDirs = ['/usr/bin/', '/usr/local/bin/', '/opt/'];
        $isAllowed = false;
        foreach ($allowedDirs as $dir) {
            if (strpos($ffmpegPath, $dir) === 0) {
                $isAllowed = true;
                break;
            }
        }
        
        if (!$isAllowed) {
            $errors[] = "FFmpeg path must be in an allowed directory";
        } elseif (!file_exists($ffmpegPath) || !is_executable($ffmpegPath)) {
            $errors[] = "FFmpeg path is not valid or executable";
        }
    }
    
    // Validate FFprobe path  
    if (!empty($input['ffprobe_path'])) {
        $ffprobePath = sanitizeInput($input['ffprobe_path'], 'path');
        
        // SECURITY: Same restrictions as FFmpeg
        $allowedDirs = ['/usr/bin/', '/usr/local/bin/', '/opt/'];
        $isAllowed = false;
        foreach ($allowedDirs as $dir) {
            if (strpos($ffprobePath, $dir) === 0) {
                $isAllowed = true;
                break;
            }
        }
        
        if (!$isAllowed) {
            $errors[] = "FFprobe path must be in an allowed directory";
        } elseif (!file_exists($ffprobePath) || !is_executable($ffprobePath)) {
            $errors[] = "FFprobe path is not valid or executable";
        }
    }
    
    // Validate web port
    if (isset($input['webport'])) {
        $port = (int)$input['webport'];
        if ($port < 1024 || $port > 65535) {
            $errors[] = "Web port must be between 1024 and 65535";
        }
        // SECURITY: Block commonly attacked ports
        $blockedPorts = [22, 23, 25, 53, 110, 143, 993, 995];
        if (in_array($port, $blockedPorts)) {
            $errors[] = "Port $port is not allowed for security reasons";
        }
    }
    
    // Validate web IP
    if (!empty($input['webip'])) {
        $ip = sanitizeInput($input['webip'], 'ip');
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $errors[] = "Invalid IP address format";
        }
        // SECURITY: Block private IPs if needed
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
            // Uncomment if you want to block private IPs
            // $errors[] = "Private IP addresses are not allowed";
        }
    }
    
    // Validate logo URL
    if (!empty($input['logourl'])) {
        $url = sanitizeInput($input['logourl'], 'url');
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            $errors[] = "Invalid logo URL format";
        }
        // SECURITY: Only allow HTTPS
        if (!empty($url) && strpos($url, 'https://') !== 0) {
            $errors[] = "Logo URL must use HTTPS";
        }
    }
    
    // Validate HLS folder
    if (!empty($input['hlsfolder'])) {
        $folder = sanitizeInput($input['hlsfolder'], 'alphanumeric');
        if (strlen($folder) > 50) {
            $errors[] = "HLS folder name is too long (max 50 characters)";
        }
        if (strlen($folder) < 3) {
            $errors[] = "HLS folder name is too short (min 3 characters)";
        }
    }
    
    // Validate user agent
    if (!empty($input['user_agent'])) {
        if (strlen($input['user_agent']) > 255) {
            $errors[] = "User agent string is too long";
        }
        // SECURITY: Block potentially malicious user agents
        $blockedPatterns = ['<script', 'javascript:', 'eval(', 'exec('];
        foreach ($blockedPatterns as $pattern) {
            if (stripos($input['user_agent'], $pattern) !== false) {
                $errors[] = "User agent contains invalid characters";
                break;
            }
        }
    }
    
    return $errors;
}

/**
 * SECURITY: Secure directory creation with enhanced validation
 */
function createSecureDirectory(string $path): bool
{
    // SECURITY: Validate and sanitize path
    $path = sanitizeInput($path, 'alphanumeric');
    
    // SECURITY: Strict base path validation
    $basePath = '/home/fos-streaming/fos/www/';
    $realBasePath = realpath($basePath);
    
    if (!$realBasePath) {
        error_log("SECURITY: Base path does not exist: $basePath");
        return false;
    }
    
    // SECURITY: Construct safe target path
    $targetPath = $realBasePath . DIRECTORY_SEPARATOR . $path;
    
    // SECURITY: Additional path traversal protection
    if (strpos($targetPath, '..') !== false) {
        error_log("SECURITY: Path traversal attempt detected: $path");
        return false;
    }
    
    // SECURITY: Ensure target is within base path
    if (strpos($targetPath, $realBasePath) !== 0) {
        error_log("SECURITY: Directory creation outside base path attempted: $targetPath");
        return false;
    }
    
    // Create directory if it doesn't exist
    if (!is_dir($targetPath)) {
        if (!mkdir($targetPath, 0750, true)) {
            error_log("SECURITY: Failed to create directory: $targetPath");
            return false;
        }
    }
    
    // SECURITY: Set restrictive permissions
    chmod($targetPath, 0750);
    
    // SECURITY: Set proper ownership if possible
    $user = posix_getpwnam('fos-streaming');
    if ($user !== false) {
        chown($targetPath, $user['uid']);
        chgrp($targetPath, $user['gid']);
    }
    
    return true;
}

/**
 * SECURITY: Enhanced logging with security considerations
 */
function logSettingsChange(array $changes): void
{
    // SECURITY: Sanitize log data
    $sanitizedChanges = [];
    foreach ($changes as $key => $change) {
        $sanitizedChanges[$key] = [
            'old' => is_string($change['old']) ? substr($change['old'], 0, 100) : $change['old'],
            'new' => is_string($change['new']) ? substr($change['new'], 0, 100) : $change['new']
        ];
    }
    
    $logData = [
        'timestamp' => date('Y-m-d H:i:s'),
        'user' => sanitizeInput($_SESSION['username'] ?? $_SESSION['user_id'] ?? 'unknown'),
        'ip' => sanitizeInput($_SERVER['REMOTE_ADDR'] ?? 'unknown', 'ip'),
        'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 255),
        'changes' => $sanitizedChanges
    ];
    
    $logDir = '/var/log/fos-streaming/';
    $logFile = $logDir . 'settings.log';
    
    // SECURITY: Ensure log directory exists and is secure
    if (!is_dir($logDir)) {
        mkdir($logDir, 0750, true);
    }
    
    // SECURITY: Check permissions before writing
    if (is_writable($logDir)) {
        file_put_contents($logFile, json_encode($logData) . "\n", FILE_APPEND | LOCK_EX);
        // SECURITY: Set secure log file permissions
        chmod($logFile, 0640);
    } else {
        error_log("SECURITY: Cannot write to log directory: $logDir");
    }
}

/**
 * COMPATIBILITY FUNCTION: Wrapper for nginx config generation
 * Maintains compatibility with existing generatEginxConfPort function
 */
function secureGenerateNginxConfig(int $port): bool
{
    // SECURITY: Validate port range
    if ($port < 1024 || $port > 65535) {
        error_log("SECURITY: Invalid port for nginx config: $port");
        return false;
    }
    
    // COMPATIBILITY: Call existing function if it exists
    if (function_exists('generatEginxConfPort')) {
        try {
            generatEginxConfPort($port);
            return true;
        } catch (Exception $e) {
            error_log("SECURITY: Legacy nginx config generation failed: " . $e->getMessage());
            return false;
        }
    }
    
    // Fallback: Use our secure version
    return generateNginxConfPort($port);
}

// CSRF Protection (compatible with both old and new systems)
$csrfToken = '';
if (function_exists('generateCSRFToken')) {
    $csrfToken = generateCSRFToken();
} else {
    // SECURITY: Enhanced fallback CSRF token generation
    if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_time'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    
    // SECURITY: Token expiration (30 minutes)
    if (time() - $_SESSION['csrf_token_time'] > 1800) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    
    $csrfToken = $_SESSION['csrf_token'];
}

// SECURITY: Rate limiting for form submissions
$rateLimitKey = 'settings_submit_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
if (!isset($_SESSION[$rateLimitKey])) {
    $_SESSION[$rateLimitKey] = ['count' => 0, 'last_attempt' => 0];
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit'])) {
    
    // SECURITY: Rate limiting check
    $now = time();
    if ($now - $_SESSION[$rateLimitKey]['last_attempt'] < 60) {
        $_SESSION[$rateLimitKey]['count']++;
        if ($_SESSION[$rateLimitKey]['count'] > 5) {
            $message['type'] = "error";
            $message['message'] = "Too many attempts. Please wait before trying again.";
            error_log("SECURITY: Rate limit exceeded for IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            goto skip_processing;
        }
    } else {
        $_SESSION[$rateLimitKey] = ['count' => 1, 'last_attempt' => $now];
    }
    
    // CSRF validation (compatible approach)
    $validCsrf = false;
    if (function_exists('validateCSRFToken')) {
        $validCsrf = validateCSRFToken($_POST['csrf_token'] ?? '');
    } else {
        // SECURITY: Enhanced fallback CSRF check with timing attack protection
        $validCsrf = isset($_POST['csrf_token']) && 
                    isset($_SESSION['csrf_token']) && 
                    hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
    }
    
    if (!$validCsrf) {
        $message['type'] = "error";
        $message['message'] = "Security token validation failed. Please try again.";
        error_log("SECURITY: CSRF validation failed for IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    } else {
        
        // Validate input
        $validationErrors = validateSettingsInput($_POST);
        
        if (!empty($validationErrors)) {
            $message['type'] = "error";
            $message['message'] = implode("<br>", $validationErrors);
        } else {
            
            // Track changes for logging
            $changes = [];
            $requiresRestart = false;
            
            // COMPATIBILITY: Maintain exact same field updates as original
            try {
                // FFmpeg path
                if (isset($_POST['ffmpeg_path']) && $_POST['ffmpeg_path'] !== $setting->ffmpeg_path) {
                    $newPath = sanitizeInput($_POST['ffmpeg_path'], 'path');
                    $changes['ffmpeg_path'] = [
                        'old' => $setting->ffmpeg_path,
                        'new' => $newPath
                    ];
                    $setting->ffmpeg_path = $newPath;
                }
                
                // FFprobe path
                if (isset($_POST['ffprobe_path']) && $_POST['ffprobe_path'] !== $setting->ffprobe_path) {
                    $newPath = sanitizeInput($_POST['ffprobe_path'], 'path');
                    $changes['ffprobe_path'] = [
                        'old' => $setting->ffprobe_path,
                        'new' => $newPath
                    ];
                    $setting->ffprobe_path = $newPath;
                }
                
                // Web port (with nginx config regeneration)
                if (isset($_POST['webport']) && $_POST['webport'] != $setting->webport) {
                    $oldPort = $setting->webport;
                    $newPort = (int)$_POST['webport'];
                    
                    if ($newPort === 0) {
                        $newPort = 8000; // COMPATIBILITY: Same default as original
                    }
                    
                    $changes['webport'] = [
                        'old' => $oldPort,
                        'new' => $newPort
                    ];
                    
                    $setting->webport = $newPort;
                    
                    // Generate nginx config (secure version)
                    if (secureGenerateNginxConfig($newPort)) {
                        $requiresRestart = true;
                    } else {
                        throw new Exception("Configuration update failed");
                    }
                }
                
                // Web IP
                if (isset($_POST['webip']) && $_POST['webip'] !== $setting->webip) {
                    $newIp = sanitizeInput($_POST['webip'], 'ip');
                    $changes['webip'] = [
                        'old' => $setting->webip,
                        'new' => $newIp
                    ];
                    $setting->webip = $newIp;
                }
                
                // Logo URL
                if (isset($_POST['logourl']) && $_POST['logourl'] !== $setting->logourl) {
                    $newUrl = sanitizeInput($_POST['logourl'], 'url');
                    $changes['logourl'] = [
                        'old' => $setting->logourl,
                        'new' => $newUrl
                    ];
                    $setting->logourl = $newUrl;
                }
                
                // HLS folder
                if (isset($_POST['hlsfolder']) && $_POST['hlsfolder'] !== $setting->hlsfolder) {
                    $oldFolder = $setting->hlsfolder;
                    $newFolder = sanitizeInput($_POST['hlsfolder'], 'alphanumeric');
                    
                    // Create directory securely
                    if (createSecureDirectory($newFolder)) {
                        $changes['hlsfolder'] = [
                            'old' => $oldFolder,
                            'new' => $newFolder
                        ];
                        $setting->hlsfolder = $newFolder;
                    } else {
                        throw new Exception("Directory creation failed");
                    }
                }
                
                // User agent
                if (isset($_POST['user_agent']) && $_POST['user_agent'] !== $setting->user_agent) {
                    $newUserAgent = sanitizeInput($_POST['user_agent']);
                    $changes['user_agent'] = [
                        'old' => $setting->user_agent,
                        'new' => $newUserAgent
                    ];
                    $setting->user_agent = $newUserAgent;
                }
                
                // Save settings
                $setting->save();
                
                // Log changes for security audit
                if (!empty($changes)) {
                    logSettingsChange($changes);
                }
                
                // Reset rate limiting on successful save
                $_SESSION[$rateLimitKey] = ['count' => 0, 'last_attempt' => 0];
                
                $message['type'] = "success";
                $message['message'] = "Settings saved successfully";
                
                // COMPATIBILITY: Handle restart message exactly like original
                if ($requiresRestart) {
                    $restartMessage = "Restart nginx and go to the following url: http://" . 
                                    ($_SERVER['SERVER_ADDR'] ?? 'localhost') . ":" . 
                                    $setting->webport . "/settings.php";
                    
                    // COMPATIBILITY: Use die() like original for restart scenario
                    die($restartMessage);
                } else {
                    // COMPATIBILITY: Use redirect function if available
                    if (function_exists('redirect')) {
                        redirect("settings.php", 1000);
                    } else {
                        header("Location: settings.php");
                        exit();
                    }
                }
                
            } catch (Exception $e) {
                $message['type'] = "error";
                $message['message'] = "Error saving settings. Please try again.";
                
                // SECURITY: Log detailed error but don't expose to user
                error_log("SECURITY: Settings save error: " . $e->getMessage() . " | IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            }
        }
    }
    
    skip_processing:
}

// COMPATIBILITY: Render template exactly like original
// This ensures compatibility with existing Blade templates
if (isset($template) && is_object($template)) {
    try {
        echo $template->view()->make('manage_settings')
            ->with('setting', $setting)
            ->with('message', $message)
            ->with('csrf_token', $csrfToken) // Add CSRF token for template
            ->render();
    } catch (Exception $e) {
        // SECURITY: Don't expose template errors to user
        error_log("SECURITY: Template rendering error: " . $e->getMessage());
        
        // Simple fallback HTML
        echo "<!DOCTYPE html><html><head><title>Settings Error</title></head><body>";
        echo "<h1>Settings Page Error</h1>";
        echo "<p>Service temporarily unavailable. Please try again later.</p>";
        echo "<a href='dashboard.php'>Return to Dashboard</a>";
        echo "</body></html>";
    }
} else {
    // Fallback if template object doesn't exist
    echo "<!DOCTYPE html><html><head><title>Configuration Error</title></head><body>";
    echo "<h1>Configuration Error</h1>";
    echo "<p>Service temporarily unavailable. Please check configuration.</p>";
    echo "</body></html>";
}
?>

<?php
declare(strict_types=1);

/**
 * FOS-Streaming Secure Settings Page
 * FULLY BACKWARD COMPATIBLE with existing system
 * PHP 8.1+ compatible with security enhancements
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

// Security enhancements
function validateSettingsInput(array $input): array
{
    $errors = [];
    
    // Validate FFmpeg path
    if (!empty($input['ffmpeg_path'])) {
        $ffmpegPath = realpath($input['ffmpeg_path']);
        if (!$ffmpegPath || !is_executable($ffmpegPath)) {
            $errors[] = "FFmpeg path is not valid or executable";
        }
    }
    
    // Validate FFprobe path  
    if (!empty($input['ffprobe_path'])) {
        $ffprobePath = realpath($input['ffprobe_path']);
        if (!$ffprobePath || !is_executable($ffprobePath)) {
            $errors[] = "FFprobe path is not valid or executable";
        }
    }
    
    // Validate web port
    if (isset($input['webport'])) {
        $port = (int)$input['webport'];
        if ($port < 1024 || $port > 65535) {
            $errors[] = "Web port must be between 1024 and 65535";
        }
    }
    
    // Validate web IP
    if (!empty($input['webip'])) {
        if (!filter_var($input['webip'], FILTER_VALIDATE_IP)) {
            $errors[] = "Invalid IP address format";
        }
    }
    
    // Validate logo URL
    if (!empty($input['logourl'])) {
        if (!filter_var($input['logourl'], FILTER_VALIDATE_URL)) {
            $errors[] = "Invalid logo URL format";
        }
    }
    
    // Validate HLS folder
    if (!empty($input['hlsfolder'])) {
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $input['hlsfolder'])) {
            $errors[] = "HLS folder name can only contain letters, numbers, underscore and dash";
        }
    }
    
    return $errors;
}

/**
 * COMPATIBILITY FUNCTION: Wrapper for nginx config generation
 * Maintains compatibility with existing generatEginxConfPort function
 */
function secureGenerateNginxConfig(int $port): bool
{
    // COMPATIBILITY: Call existing function if it exists
    if (function_exists('generatEginxConfPort')) {
        try {
            generatEginxConfPort($port);
            return true;
        } catch (Exception $e) {
            error_log("Legacy nginx config generation failed: " . $e->getMessage());
            return false;
        }
    }
    
    // Fallback: Use our secure version
    return generateNginxConfPort($port);
}

/**
 * Secure directory creation with proper permissions
 */
function createSecureDirectory(string $path): bool
{
    // Validate path is within allowed area
    $basePath = '/home/fos-streaming/fos/www/';
    $realBasePath = realpath($basePath);
    $targetPath = $basePath . basename($path);
    
    if (!$realBasePath) {
        return false;
    }
    
    // Create directory if it doesn't exist
    if (!is_dir($targetPath)) {
        if (!mkdir($targetPath, 0755, true)) {
            return false;
        }
    }
    
    // Set secure permissions
    chmod($targetPath, 0755);
    
    // Verify path is safe
    $realTargetPath = realpath($targetPath);
    if (!$realTargetPath || strpos($realTargetPath, $realBasePath) !== 0) {
        return false;
    }
    
    return true;
}

/**
 * Log settings changes for security audit
 */
function logSettingsChange(array $changes): void
{
    $logData = [
        'timestamp' => date('Y-m-d H:i:s'),
        'user' => $_SESSION['username'] ?? $_SESSION['user_id'] ?? 'unknown',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'changes' => $changes
    ];
    
    $logFile = '/var/log/fos-streaming/settings.log';
    if (is_writable(dirname($logFile))) {
        file_put_contents($logFile, json_encode($logData) . "\n", FILE_APPEND | LOCK_EX);
    }
}

// CSRF Protection (compatible with both old and new systems)
$csrfToken = '';
if (function_exists('generateCSRFToken')) {
    $csrfToken = generateCSRFToken();
} else {
    // Fallback for old system
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    $csrfToken = $_SESSION['csrf_token'];
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit'])) {
    
    // CSRF validation (compatible approach)
    $validCsrf = false;
    if (function_exists('validateCSRFToken')) {
        $validCsrf = validateCSRFToken($_POST['csrf_token'] ?? '');
    } else {
        // Fallback CSRF check
        $validCsrf = isset($_POST['csrf_token']) && 
                    isset($_SESSION['csrf_token']) && 
                    hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
    }
    
    if (!$validCsrf) {
        $message['type'] = "error";
        $message['message'] = "Security token validation failed. Please try again.";
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
                    $changes['ffmpeg_path'] = [
                        'old' => $setting->ffmpeg_path,
                        'new' => $_POST['ffmpeg_path']
                    ];
                    $setting->ffmpeg_path = $_POST['ffmpeg_path'];
                }
                
                // FFprobe path
                if (isset($_POST['ffprobe_path']) && $_POST['ffprobe_path'] !== $setting->ffprobe_path) {
                    $changes['ffprobe_path'] = [
                        'old' => $setting->ffprobe_path,
                        'new' => $_POST['ffprobe_path']
                    ];
                    $setting->ffprobe_path = $_POST['ffprobe_path'];
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
                        throw new Exception("Failed to generate nginx configuration");
                    }
                }
                
                // Web IP
                if (isset($_POST['webip']) && $_POST['webip'] !== $setting->webip) {
                    $changes['webip'] = [
                        'old' => $setting->webip,
                        'new' => $_POST['webip']
                    ];
                    $setting->webip = $_POST['webip'];
                }
                
                // Logo URL
                if (isset($_POST['logourl']) && $_POST['logourl'] !== $setting->logourl) {
                    $changes['logourl'] = [
                        'old' => $setting->logourl,
                        'new' => $_POST['logourl']
                    ];
                    $setting->logourl = $_POST['logourl'];
                }
                
                // HLS folder
                if (isset($_POST['hlsfolder']) && $_POST['hlsfolder'] !== $setting->hlsfolder) {
                    $oldFolder = $setting->hlsfolder;
                    $newFolder = $_POST['hlsfolder'];
                    
                    // Create directory securely
                    if (createSecureDirectory($newFolder)) {
                        $changes['hlsfolder'] = [
                            'old' => $oldFolder,
                            'new' => $newFolder
                        ];
                        $setting->hlsfolder = $newFolder;
                    } else {
                        throw new Exception("Failed to create HLS directory: " . $newFolder);
                    }
                }
                
                // User agent
                if (isset($_POST['user_agent']) && $_POST['user_agent'] !== $setting->user_agent) {
                    $changes['user_agent'] = [
                        'old' => $setting->user_agent,
                        'new' => $_POST['user_agent']
                    ];
                    $setting->user_agent = $_POST['user_agent'];
                }
                
                // Save settings
                $setting->save();
                
                // Log changes for security audit
                if (!empty($changes)) {
                    logSettingsChange($changes);
                }
                
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
                $message['message'] = "Error saving settings: " . htmlspecialchars($e->getMessage());
                
                // Log error for debugging
                error_log("Settings save error: " . $e->getMessage());
            }
        }
    }
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
        // Fallback if template system fails
        error_log("Template rendering error: " . $e->getMessage());
        
        // Simple fallback HTML
        echo "<!DOCTYPE html><html><head><title>Settings Error</title></head><body>";
        echo "<h1>Settings Page Error</h1>";
        echo "<p>Template system error. Please check logs.</p>";
        echo "<a href='dashboard.php'>Return to Dashboard</a>";
        echo "</body></html>";
    }
} else {
    // Fallback if template object doesn't exist
    echo "<!DOCTYPE html><html><head><title>Configuration Error</title></head><body>";
    echo "<h1>Configuration Error</h1>";
    echo "<p>Template system not initialized. Please check configuration.</p>";
    echo "</body></html>";
}

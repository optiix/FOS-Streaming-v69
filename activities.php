<?php
declare(strict_types=1);

/**
 * FOS-Streaming Activities Management
 * PHP 8.1+ compatible with security enhancements
 */

require_once 'config.php';

// SECURITY: Check authentication
logincheck();

// SECURITY: Initialize message array
$message = [];

// SECURITY: Rate limiting for bulk operations
session_start();
$rateLimitKey = 'activities_operations_' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
if (!isset($_SESSION[$rateLimitKey])) {
    $_SESSION[$rateLimitKey] = ['count' => 0, 'last_operation' => 0];
}

/**
 * SECURITY: Basic input validation and sanitization
 */
function validateInput(string $input, int $maxLength = 50): ?string
{
    if (empty($input)) {
        return null;
    }
    
    $sanitized = trim($input);
    if (!is_numeric($sanitized) || (int)$sanitized <= 0) {
        return null;
    }
    
    return substr($sanitized, 0, $maxLength);
}

/**
 * SECURITY: Check rate limiting for operations
 */
function checkRateLimit(): bool
{
    global $rateLimitKey;
    
    $now = time();
    if ($now - $_SESSION[$rateLimitKey]['last_operation'] < 5) {
        $_SESSION[$rateLimitKey]['count']++;
        if ($_SESSION[$rateLimitKey]['count'] > 3) {
            return false;
        }
    } else {
        $_SESSION[$rateLimitKey] = ['count' => 1, 'last_operation' => $now];
    }
    
    return true;
}

/**
 * SECURITY: Log activity operations for audit
 */
function logActivityOperation(string $operation, array $context = []): void
{
    $logData = [
        'timestamp' => date('Y-m-d H:i:s'),
        'operation' => $operation,
        'user' => $_SESSION['username'] ?? $_SESSION['user_id'] ?? 'unknown',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'context' => $context
    ];
    
    $logFile = '/var/log/fos-streaming/activities.log';
    if (is_writable(dirname($logFile))) {
        file_put_contents($logFile, json_encode($logData) . "\n", FILE_APPEND | LOCK_EX);
    }
}

// SECURITY: Handle delete all activities with protection
if (isset($_GET['delete_all'])) {
    
    // SECURITY: Rate limiting check
    if (!checkRateLimit()) {
        $message['type'] = "error";
        $message['message'] = "Too many operations. Please wait before trying again.";
        logActivityOperation('delete_all_rate_limited');
    } else {
        
        try {
            // SECURITY: Get count before deletion for logging
            $activityCount = Activity::count();
            
            if ($activityCount > 1000) {
                // SECURITY: For large datasets, use chunked deletion
                $deletedCount = 0;
                Activity::chunk(100, function ($activities) use (&$deletedCount) {
                    foreach ($activities as $activity) {
                        $activity->delete();
                        $deletedCount++;
                    }
                });
                
                $message['type'] = "success";
                $message['message'] = "All activities deleted successfully ($deletedCount records)";
                
            } else {
                // SECURITY: Standard deletion for smaller datasets
                $deletedActivities = Activity::all();
                $deletedCount = $deletedActivities->count();
                
                foreach ($deletedActivities as $activity) {
                    $activity->delete();
                }
                
                $message['type'] = "success";
                $message['message'] = "All activities deleted successfully ($deletedCount records)";
            }
            
            // SECURITY: Log the operation
            logActivityOperation('delete_all_activities', [
                'deleted_count' => $deletedCount ?? $activityCount
            ]);
            
        } catch (Exception $e) {
            $message['type'] = "error";
            $message['message'] = "Error deleting activities. Please try again.";
            
            // SECURITY: Log error without exposing details
            logActivityOperation('delete_all_error', [
                'error_type' => get_class($e)
            ]);
            
            error_log("SECURITY: Activities delete_all error: " . $e->getMessage());
        }
    }
}

// SECURITY: Handle single activity deletion with validation
if (isset($_GET['delete'])) {
    
    // SECURITY: Rate limiting check
    if (!checkRateLimit()) {
        $message['type'] = "error";
        $message['message'] = "Too many operations. Please wait before trying again.";
        logActivityOperation('delete_single_rate_limited');
    } else {
        
        // SECURITY: Validate input
        $activityId = validateInput($_GET['delete']);
        
        if ($activityId === null) {
            $message['type'] = "error";
            $message['message'] = "Invalid activity ID";
            logActivityOperation('delete_single_invalid_id', ['provided_id' => $_GET['delete'] ?? 'empty']);
        } else {
            
            try {
                $activity = Activity::find((int)$activityId);
                
                if (!$activity) {
                    $message['type'] = "error";
                    $message['message'] = "Activity not found";
                    logActivityOperation('delete_single_not_found', ['activity_id' => $activityId]);
                } else {
                    
                    // SECURITY: Store info before deletion for logging
                    $activityInfo = [
                        'id' => $activity->id,
                        'user_id' => $activity->user_id ?? 'unknown',
                        'stream_id' => $activity->stream_id ?? 'unknown'
                    ];
                    
                    $activity->delete();
                    
                    $message['type'] = "success";
                    $message['message'] = "Activity deleted successfully";
                    
                    logActivityOperation('delete_single_activity', $activityInfo);
                }
                
            } catch (Exception $e) {
                $message['type'] = "error";
                $message['message'] = "Error deleting activity. Please try again.";
                
                // SECURITY: Log error without exposing details
                logActivityOperation('delete_single_error', [
                    'activity_id' => $activityId,
                    'error_type' => get_class($e)
                ]);
                
                error_log("SECURITY: Activity delete error: " . $e->getMessage() . " | ID: " . $activityId);
            }
        }
    }
}

// SECURITY: Fetch activities with pagination and error handling
try {
    // SECURITY: Only fetch completed activities (with end date)
    $activities = Activity::where('date_end', '<>', '0000-00-00 00:00:00')
                         ->orderBy('date_start', 'desc')
                         ->limit(500) // SECURITY: Limit results to prevent memory issues
                         ->get();
    
    // SECURITY: Log successful data fetch
    logActivityOperation('view_activities', [
        'activity_count' => $activities->count()
    ]);
    
} catch (Exception $e) {
    // SECURITY: Handle database errors gracefully
    $activities = collect(); // Empty collection
    $message['type'] = "error";
    $message['message'] = "Error loading activities. Please try again.";
    
    logActivityOperation('view_activities_error', [
        'error_type' => get_class($e)
    ]);
    
    error_log("SECURITY: Activities fetch error: " . $e->getMessage());
}

// SECURITY: Render template with error handling
try {
    echo $template->view()->make('activities')
        ->with('activities', $activities)
        ->with('message', $message)
        ->render();
        
} catch (Exception $e) {
    // SECURITY: Fallback if template rendering fails
    error_log("SECURITY: Activities template error: " . $e->getMessage());
    
    echo "<!DOCTYPE html><html><head><title>Activities Error</title></head><body>";
    echo "<h1>Activities Page Error</h1>";
    echo "<p>Unable to load activities page. Please check logs and try again.</p>";
    echo "<a href='dashboard.php'>Return to Dashboard</a>";
    echo "</body></html>";
}
?>

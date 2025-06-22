<?php

/**
 * FOS-Streaming cron.php - SECURE VERSION
 * BACKWARD COMPATIBLE - Original logic maintained with security enhancements
 * Works with traditional cron, web access, and systemd
 * 
 * SECURITY FIXES:
 * - Command injection prevention
 * - Input validation for all shell commands
 * - Safe PID handling
 * - Path traversal protection
 * - Enhanced logging with security events
 */

// ORIGINAL ACCESS CONTROL: Keep exact same logic
if (isset($_SERVER['SERVER_ADDR'])) {
    if ($_SERVER['REMOTE_ADDR'] != $_SERVER['SERVER_ADDR']) {
        die('access is not permitted');
    }
}

// Enhanced but compatible execution settings
set_time_limit(300); // 5 minutes max
ini_set('memory_limit', '256M');

// ORIGINAL: Include config
include('config.php');

// SECURITY FUNCTIONS - Added for protection
function validateStreamUrl($url)
{
    if (empty($url)) return false;
    
    // Allow only safe protocols
    if (!preg_match('/^(http|https|rtmp|rtmps|udp|rtp|file):\/\//', $url)) {
        return false;
    }
    
    // Block shell metacharacters that could cause command injection
    if (preg_match('/[;&|`$(){}\\[\\]<>\\\\]/', $url)) {
        return false;
    }
    
    // Additional safety: limit URL length
    if (strlen($url) > 2048) {
        return false;
    }
    
    return true;
}

function validatePid($pid)
{
    $pid = filter_var($pid, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1, 'max_range' => 65535]
    ]);
    
    return $pid !== false ? $pid : null;
}

function safeFFProbeExec($ffprobePath, $url)
{
    // Validate inputs
    if (!validateStreamUrl($url)) {
        throw new InvalidArgumentException('Invalid stream URL');
    }
    
    if (!file_exists($ffprobePath) || !is_executable($ffprobePath)) {
        throw new InvalidArgumentException('FFprobe path invalid');
    }
    
    // Use escapeshellarg for the URL
    $command = escapeshellcmd($ffprobePath) . 
               ' -analyzeduration 1000000 -probesize 9000000 -i ' . 
               escapeshellarg($url) . 
               ' -v quiet -print_format json -show_streams 2>&1';
    
    return shell_exec($command);
}

function safeKillProcess($pid)
{
    $validPid = validatePid($pid);
    if ($validPid === null) {
        return false;
    }
    
    // Double-check process exists before killing
    if (!safePidCheck($validPid)) {
        return false;
    }
    
    $command = 'kill -9 ' . (int)$validPid;
    shell_exec($command);
    return true;
}

function safeCleanupFiles($hlsFolder, $streamId)
{
    // Validate inputs
    $hlsFolder = preg_replace('/[^a-zA-Z0-9_-]/', '', $hlsFolder);
    $streamId = filter_var($streamId, FILTER_VALIDATE_INT);
    
    if (empty($hlsFolder) || $streamId === false) {
        return false;
    }
    
    // Build safe path
    $basePath = '/home/fos-streaming/fos/www';
    $targetPath = $basePath . '/' . $hlsFolder . '/' . $streamId . '*';
    
    // Additional safety: ensure path is within expected directory
    $realBasePath = realpath($basePath);
    $hlsDir = $basePath . '/' . $hlsFolder;
    
    if (is_dir($hlsDir)) {
        $realHlsPath = realpath($hlsDir);
        if ($realHlsPath === false || strpos($realHlsPath, $realBasePath) !== 0) {
            return false;
        }
    }
    
    $command = '/bin/rm -rf ' . escapeshellarg($targetPath);
    shell_exec($command);
    return true;
}

// Enhanced logging function (optional, safe fallback)
function cronLog($message, $level = 'info')
{
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] [$level] $message";
    
    // Try to log to file, but don't break if it fails
    $logFile = '/var/log/fos-streaming/cron.log';
    if (is_dir(dirname($logFile)) && is_writable(dirname($logFile))) {
        file_put_contents($logFile, $logEntry . "\n", FILE_APPEND | LOCK_EX);
    }
    
    // Always log to error log as fallback
    error_log("FOS-CRON: $message");
}

// Enhanced but compatible PID checking
function safePidCheck($pid)
{
    // Use existing checkPid function if available
    if (function_exists('checkPid')) {
        return checkPid($pid);
    }
    
    // ORIGINAL: Fallback to original logic
    $pid = (int)$pid;
    if ($pid <= 0) return false;
    
    $output = [];
    exec("ps $pid", $output);
    return count($output) >= 2;
}

// Enhanced stream restart with original logic preserved
function restartStreamCompat($stream, $setting, $streamNumber = 1)
{
    try {
        cronLog("Attempting to restart stream {$stream->id} with URL $streamNumber");
        
        // ORIGINAL: URL selection logic
        $url = $stream->streamurl;
        if ($streamNumber == 2) {
            $url = $stream->streamurl2;
        } elseif ($streamNumber == 3) {
            $url = $stream->streamurl3;
        }
        
        if (empty($url)) {
            cronLog("No URL available for stream {$stream->id} URL $streamNumber");
            return false;
        }
        
        // SECURE: Check stream with ffprobe using safe execution
        try {
            $checkstreamurl = safeFFProbeExec($setting->ffprobe_path, $url);
            $streaminfo = json_decode($checkstreamurl, true);
        } catch (Exception $e) {
            cronLog("FFprobe execution failed for stream {$stream->id}: " . $e->getMessage());
            return false;
        }
        
        if (!$streaminfo) {
            cronLog("Stream validation failed for {$stream->id} URL $streamNumber");
            return false;
        }
        
        // ORIGINAL: Use getTranscode function exactly as before
        $transcodeCmd = getTranscode($stream->id, $streamNumber == 1 ? null : $streamNumber);
        
        if (empty($transcodeCmd)) {
            cronLog("Failed to generate transcode command for stream {$stream->id}");
            return false;
        }
        
        // SECURE: Basic validation of transcode command before execution
        if (preg_match('/[;&|`]/', $transcodeCmd)) {
            cronLog("Unsafe transcode command detected for stream {$stream->id}");
            return false;
        }
        
        // ORIGINAL: Execute transcode and get PID
        $pid = shell_exec($transcodeCmd);
        $pid = trim($pid);
        
        if (!is_numeric($pid) || (int)$pid <= 0) {
            cronLog("Invalid PID returned for stream {$stream->id}: $pid");
            return false;
        }
        
        // ORIGINAL: Update stream fields exactly as before
        $stream->pid = $pid;
        $stream->running = 1;
        $stream->status = 1;
        $stream->checker = $streamNumber;
        
        // ORIGINAL: Extract codec information (same logic as start_stream)
        $video = "";
        $audio = "";
        if (is_array($streaminfo) && isset($streaminfo['streams'])) {
            foreach ($streaminfo['streams'] as $info) {
                if ($video == '') {
                    $video = ($info['codec_type'] == 'video' ? $info['codec_name'] : '');
                }
                if ($audio == '') {
                    $audio = ($info['codec_type'] == 'audio' ? $info['codec_name'] : '');
                }
            }
            $stream->video_codec_name = $video;
            $stream->audio_codec_name = $audio;
        }
        
        cronLog("Stream {$stream->id} restarted successfully with PID $pid");
        return true;
        
    } catch (Exception $e) {
        cronLog("Exception restarting stream {$stream->id}: " . $e->getMessage());
        return false;
    }
}

// Enhanced cleanup with original commands
function cleanupStreamCompat($stream, $setting)
{
    try {
        // SECURE: Kill process if running with safe validation
        if (!empty($stream->pid)) {
            if (!safeKillProcess($stream->pid)) {
                cronLog("Failed to kill process safely: " . $stream->pid);
            } else {
                cronLog("Killed process {$stream->pid} for stream {$stream->id}");
            }
        }
        
        // SECURE: Clean up files with path validation
        $hlsFolder = $setting->hlsfolder;
        if (!empty($hlsFolder)) {
            if (!safeCleanupFiles($hlsFolder, $stream->id)) {
                cronLog("Failed to cleanup files safely for stream {$stream->id}");
            } else {
                cronLog("Cleaned up files for stream {$stream->id}");
            }
        }
        
    } catch (Exception $e) {
        cronLog("Cleanup error for stream {$stream->id}: " . $e->getMessage());
    }
}

// MAIN CRON LOGIC: Keep EXACT same flow as original
try {
    cronLog("Cron job started");
    
    $setting = Setting::first();
    if (!$setting) {
        cronLog("No settings found in database");
        exit(1);
    }
    
    $processedStreams = 0;
    $restartedStreams = 0;
    
    // ORIGINAL: Process streams where pid != 0 and running = 1
    foreach (Stream::where('pid', '!=', 0)->where('running', '=', 1)->get() as $stream) {
        $processedStreams++;
        
        // ORIGINAL: Check if PID is still running
        if (!safePidCheck($stream->pid)) {
            cronLog("Process {$stream->pid} not running for stream {$stream->id}, attempting restart");
            
            // ORIGINAL: Reset checker
            $stream->checker = 0;
            
            // SECURE: Check primary URL first with safe execution
            try {
                $checkstreamurl = safeFFProbeExec($setting->ffprobe_path, $stream->streamurl);
                $streaminfo = json_decode($checkstreamurl, true);
            } catch (Exception $e) {
                cronLog("FFprobe failed for stream {$stream->id}: " . $e->getMessage());
                $streaminfo = null;
            }
            
            if ($streaminfo) {
                // ORIGINAL: Restart with primary URL using existing logic
                $transcodeCmd = getTranscode($stream->id);
                
                // SECURE: Basic validation of transcode command
                if (!empty($transcodeCmd) && !preg_match('/[;&|`]/', $transcodeCmd)) {
                    $pid = shell_exec($transcodeCmd);
                    $pid = trim($pid);
                    
                    if (is_numeric($pid) && (int)$pid > 0) {
                        $stream->pid = $pid;
                        $stream->running = 1;
                        $stream->status = 1;
                        
                        // ORIGINAL: Extract codec information
                        $video = "";
                        $audio = "";
                        if (is_array($streaminfo) && isset($streaminfo['streams'])) {
                            foreach ($streaminfo['streams'] as $info) {
                                if ($video == '') {
                                    $video = ($info['codec_type'] == 'video' ? $info['codec_name'] : '');
                                }
                                if ($audio == '') {
                                    $audio = ($info['codec_type'] == 'audio' ? $info['codec_name'] : '');
                                }
                            }
                            $stream->video_codec_name = $video;
                            $stream->audio_codec_name = $audio;
                        }
                        
                        $restartedStreams++;
                        cronLog("Restarted stream {$stream->id} with primary URL");
                    } else {
                        cronLog("Invalid PID returned for primary URL restart: $pid");
                        $streaminfo = null; // Force backup URL attempt
                    }
                } else {
                    cronLog("Unsafe or empty transcode command for stream {$stream->id}");
                    $streaminfo = null; // Force backup URL attempt
                }
            }
            
            if (!$streaminfo) {
                // ORIGINAL: Try backup URLs - EXACT same logic as original
                $stream->running = 1;
                $stream->status = 2;
                
                // ORIGINAL: Cleanup before trying backup URLs
                cleanupStreamCompat($stream, $setting);
                
                $restarted = false;
                
                // ORIGINAL: Try streamurl2
                if (!empty($stream->streamurl2)) {
                    cronLog("Trying backup URL 2 for stream {$stream->id}");
                    $stream->checker = 2;
                    
                    try {
                        $checkstreamurl = safeFFProbeExec($setting->ffprobe_path, $stream->streamurl2);
                        $streaminfo = json_decode($checkstreamurl, true);
                    } catch (Exception $e) {
                        cronLog("FFprobe failed for URL2 stream {$stream->id}: " . $e->getMessage());
                        $streaminfo = null;
                    }
                    
                    if ($streaminfo) {
                        $transcodeCmd = getTranscode($stream->id, 2);
                        
                        if (!empty($transcodeCmd) && !preg_match('/[;&|`]/', $transcodeCmd)) {
                            $pid = shell_exec($transcodeCmd);
                            $pid = trim($pid);
                            
                            if (is_numeric($pid) && (int)$pid > 0) {
                                $stream->pid = $pid;
                                $stream->running = 1;
                                $stream->status = 1;
                                
                                // ORIGINAL: Codec detection for URL2
                                $video = "";
                                $audio = "";
                                if (is_array($streaminfo) && isset($streaminfo['streams'])) {
                                    foreach ($streaminfo['streams'] as $info) {
                                        if ($video == '') {
                                            $video = ($info['codec_type'] == 'video' ? $info['codec_name'] : '');
                                        }
                                        if ($audio == '') {
                                            $audio = ($info['codec_type'] == 'audio' ? $info['codec_name'] : '');
                                        }
                                    }
                                    $stream->video_codec_name = $video;
                                    $stream->audio_codec_name = $audio;
                                }
                                
                                $restartedStreams++;
                                $restarted = true;
                                cronLog("Restarted stream {$stream->id} with backup URL 2");
                            }
                        }
                    }
                }
                
                // ORIGINAL: Try streamurl3 if url2 failed
                if (!$restarted && !empty($stream->streamurl3)) {
                    cronLog("Trying backup URL 3 for stream {$stream->id}");
                    $stream->checker = 3;
                    
                    try {
                        $checkstreamurl = safeFFProbeExec($setting->ffprobe_path, $stream->streamurl3);
                        $streaminfo = json_decode($checkstreamurl, true);
                    } catch (Exception $e) {
                        cronLog("FFprobe failed for URL3 stream {$stream->id}: " . $e->getMessage());
                        $streaminfo = null;
                    }
                    
                    if ($streaminfo) {
                        $transcodeCmd = getTranscode($stream->id, 3);
                        
                        if (!empty($transcodeCmd) && !preg_match('/[;&|`]/', $transcodeCmd)) {
                            $pid = shell_exec($transcodeCmd);
                            $pid = trim($pid);
                            
                            if (is_numeric($pid) && (int)$pid > 0) {
                                $stream->pid = $pid;
                                $stream->running = 1;
                                $stream->status = 1;

                                // ORIGINAL: Codec detection for URL3
                                $video = "";
                                $audio = "";
                                if (is_array($streaminfo) && isset($streaminfo['streams'])) {
                                    foreach ($streaminfo['streams'] as $info) {
                                        if ($video == '') {
                                            $video = ($info['codec_type'] == 'video' ? $info['codec_name'] : '');
                                        }
                                        if ($audio == '') {
                                            $audio = ($info['codec_type'] == 'audio' ? $info['codec_name'] : '');
                                        }
                                    }
                                    $stream->video_codec_name = $video;
                                    $stream->audio_codec_name = $audio;
                                }
                                
                                $restartedStreams++;
                                $restarted = true;
                                cronLog("Restarted stream {$stream->id} with backup URL 3");
                            }
                        }
                    }
                }
                
                if (!$restarted) {
                    $stream->running = 1;
                    $stream->status = 2;
                    $stream->pid = null;
                    cronLog("All URLs failed for stream {$stream->id}");
                }
            }
            
            // ORIGINAL: Save stream changes
            $stream->save();
        }
    }
    
    // ORIGINAL: Handle restreams (checker functionality) - EXACT same logic with security
    foreach (Stream::where('restream', '=', 1)->where('running', '=', 1)->get() as $stream) {
        $processedStreams++;
        
        // SECURE: Check primary URL
        try {
            $checkstreamurl = safeFFProbeExec($setting->ffprobe_path, $stream->streamurl);
            $streaminfo = json_decode($checkstreamurl, true);
        } catch (Exception $e) {
            cronLog("Restream FFprobe failed for stream {$stream->id}: " . $e->getMessage());
            $streaminfo = null;
        }
        
        if ($streaminfo) {
            $stream->checker = 0;
        } else {
            // ORIGINAL: Check backup URLs for restreams
            if (!empty($stream->streamurl2)) {
                try {
                    $checkstreamurl = safeFFProbeExec($setting->ffprobe_path, $stream->streamurl2);
                    $streaminfo = json_decode($checkstreamurl, true);
                } catch (Exception $e) {
                    $streaminfo = null;
                }
                
                if ($streaminfo) {
                    $stream->checker = 2;
                } else {
                    if (!empty($stream->streamurl3)) {
                        try {
                            $checkstreamurl = safeFFProbeExec($setting->ffprobe_path, $stream->streamurl3);
                            $streaminfo = json_decode($checkstreamurl, true);
                        } catch (Exception $e) {
                            $streaminfo = null;
                        }
                        
                        if ($streaminfo) {
                            $stream->checker = 3;
                        }
                    }
                }
            }
        }
        
        // ORIGINAL: Save restream changes
        $stream->save();
    }
    
    cronLog("Cron job completed successfully - Processed: $processedStreams, Restarted: $restartedStreams");
    
} catch (Exception $e) {
    cronLog("Cron job failed with exception: " . $e->getMessage());
    exit(1);
}

// ORIGINAL: Exit successfully
exit(0);

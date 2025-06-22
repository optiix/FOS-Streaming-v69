<?php

/**
 * FOS-Streaming cron.php
 * BACKWARD COMPATIBLE - Original logic maintained with security enhancements
 * Works with traditional cron, web access, and systemd
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
        
        // ORIGINAL: Check stream with ffprobe (same command as original)
        $checkstreamurl = shell_exec('' . $setting->ffprobe_path . ' -analyzeduration 1000000 -probesize 9000000 -i "' . $url . '" -v quiet -print_format json -show_streams 2>&1');
        $streaminfo = json_decode($checkstreamurl, true);
        
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
        // ORIGINAL: Kill process if running
        if (!empty($stream->pid) && safePidCheck($stream->pid)) {
            $pid = (int)$stream->pid;
            shell_exec("kill -9 " . $pid);
            cronLog("Killed process $pid for stream {$stream->id}");
        }
        
        // ORIGINAL: Clean up files (same command as original)
        $hlsFolder = $setting->hlsfolder;
        if (!empty($hlsFolder)) {
            // Enhanced: Basic validation but preserve original path logic
            $hlsFolder = preg_replace('/[^a-zA-Z0-9_-]/', '', $hlsFolder);
            if (!empty($hlsFolder)) {
                shell_exec("/bin/rm -r /home/fos-streaming/fos/www/" . $hlsFolder . "/" . $stream->id . "*");
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
            
            // ORIGINAL: Check primary URL first
            $checkstreamurl = shell_exec('' . $setting->ffprobe_path . ' -analyzeduration 1000000 -probesize 9000000 -i "' . $stream->streamurl . '" -v quiet -print_format json -show_streams 2>&1');
            $streaminfo = json_decode($checkstreamurl, true);
            
            if ($streaminfo) {
                // ORIGINAL: Restart with primary URL using existing logic
                $pid = shell_exec(getTranscode($stream->id));
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
                    
                    $checkstreamurl = shell_exec('' . $setting->ffprobe_path . ' -analyzeduration 1000000 -probesize 9000000 -i "' . $stream->streamurl2 . '" -v quiet -print_format json -show_streams 2>&1');
                    $streaminfo = json_decode($checkstreamurl, true);
                    
                    if ($streaminfo) {
                        $pid = shell_exec(getTranscode($stream->id, 2));
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
                
                // ORIGINAL: Try streamurl3 if url2 failed
                if (!$restarted && !empty($stream->streamurl3)) {
                    cronLog("Trying backup URL 3 for stream {$stream->id}");
                    $stream->checker = 3;
                    
                    $checkstreamurl = shell_exec('' . $setting->ffprobe_path . ' -analyzeduration 1000000 -probesize 9000000 -i "' . $stream->streamurl3 . '" -v quiet -print_format json -show_streams 2>&1');
                    $streaminfo = json_decode($checkstreamurl, true);
                    
                    if ($streaminfo) {
                        $pid = shell_exec(getTranscode($stream->id, 3));
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
    
    // ORIGINAL: Handle restreams (checker functionality) - EXACT same logic
    foreach (Stream::where('restream', '=', 1)->where('running', '=', 1)->get() as $stream) {
        $processedStreams++;
        
        // ORIGINAL: Check primary URL
        $checkstreamurl = shell_exec('' . $setting->ffprobe_path . ' -analyzeduration 1000000 -probesize 9000000 -i "' . $stream->streamurl . '" -v quiet -print_format json -show_streams 2>&1');
        $streaminfo = json_decode($checkstreamurl, true);
        
        if ($streaminfo) {
            $stream->checker = 0;
        } else {
            // ORIGINAL: Check backup URLs for restreams
            if (!empty($stream->streamurl2)) {
                $checkstreamurl = shell_exec('' . $setting->ffprobe_path . ' -analyzeduration 1000000 -probesize 9000000 -i "' . $stream->streamurl2 . '" -v quiet -print_format json -show_streams 2>&1');
                $streaminfo = json_decode($checkstreamurl, true);
                
                if ($streaminfo) {
                    $stream->checker = 2;
                } else {
                    if (!empty($stream->streamurl3)) {
                        $checkstreamurl = shell_exec('' . $setting->ffprobe_path . ' -analyzeduration 1000000 -probesize 9000000 -i "' . $stream->streamurl3 . '" -v quiet -print_format json -show_streams 2>&1');
                        $streaminfo = json_decode($checkstreamurl, true);
                        
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

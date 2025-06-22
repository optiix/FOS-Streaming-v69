<?php

/**
 * FOS-Streaming functions.php
 * BACKWARD COMPATIBLE - All original functions preserved
 * Enhanced security added underneath without breaking existing code
 */

// ORIGINAL FUNCTION: redirect - Keep exact same signature and behavior
function redirect($url, $time)
{
    // Enhanced input validation but maintain original behavior
    if (!is_string($url) && !is_numeric($url)) {
        $url = 'index.php';
    }
    
    // Convert inputs safely but maintain original types accepted
    $url = (string)$url;
    $time = (int)$time;
    
    // Security enhancement: Basic URL validation
    if (!empty($url) && !preg_match('/^https?:\/\//', $url)) {
        // For relative URLs, ensure they're safe
        $url = ltrim($url, '/');
        if (empty($url)) $url = 'index.php';
    }
    
    // ORIGINAL OUTPUT: Keep exact same format
    echo "<script>
                window.setTimeout(function(){
                    window.location.href = '" . addslashes($url) . "';
                }, " . $time . ");
            </script>";
}

// ORIGINAL LOGOUT LOGIC: Keep exactly as it was
if (isset($_GET['logout'])) {
    $_SESSION = array();
    
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time()-3600, '/');
    }
    
    session_destroy();
    header("location: index.php");
    exit();
}

// ORIGINAL FUNCTION: logincheck - Same behavior, enhanced security
function logincheck()
{
    // ORIGINAL: Check if user_id is set
    if (!isset($_SESSION['user_id'])) {
        header("location: index.php");
        exit();
    }
    
    // ENHANCEMENT: Add session timeout (but don't break existing sessions)
    if (isset($_SESSION['last_activity'])) {
        if ((time() - $_SESSION['last_activity']) > 7200) { // 2 hours
            session_destroy();
            header("location: index.php");
            exit();
        }
    }
    $_SESSION['last_activity'] = time();
}

// ORIGINAL FUNCTION: lists - Keep exact same signature
function lists($list, $column)
{
    $columns = [];
    
    // ENHANCEMENT: Add safety checks but maintain original logic
    if (!is_object($list)) {
        return $columns;
    }
    
    // ORIGINAL: Convert to array and process
    try {
        $array = $list->toArray();
        
        foreach ($array as $key => $value) {
            if (is_array($value) && isset($value[$column])) {
                array_push($columns, $value[$column]);
            }
        }
    } catch (Exception $e) {
        // Silent failure to maintain compatibility
        error_log('Lists function error: ' . $e->getMessage());
    }

    return $columns;
}

// ORIGINAL FUNCTION: checkPid - Same signature and return values
function checkPid($pid)
{
    // ENHANCEMENT: Input validation but maintain original behavior
    $pid = (int)$pid;
    
    if ($pid <= 0) {
        return false;
    }
    
    // ORIGINAL: Use ps command to check if process exists
    $output = [];
    $result = 0;
    exec("ps $pid", $output, $result);
    
    // ORIGINAL: Return true if more than 1 line (header + process)
    return count($output) >= 2 ? true : false;
}

// ORIGINAL FUNCTION: stop_stream - Keep exact same signature and logic
function stop_stream($id)
{
    try {
        $stream = Stream::find($id);
        if (!$stream) {
            return false;
        }
        
        $setting = Setting::first();
        if (!$setting) {
            return false;
        }

        // ORIGINAL: Check if PID exists and kill it
        if (checkPid($stream->pid)) {
            // ENHANCEMENT: Safer process killing
            $pid = (int)$stream->pid;
            if ($pid > 0) {
                shell_exec("kill -9 " . $pid);
            }
            
            // ORIGINAL: Clean up files
            $hlsFolder = $setting->hlsfolder;
            if (!empty($hlsFolder)) {
                // ENHANCEMENT: Basic path validation
                $hlsFolder = preg_replace('/[^a-zA-Z0-9_-]/', '', $hlsFolder);
                if (!empty($hlsFolder)) {
                    shell_exec("/bin/rm -r /home/fos-streaming/fos/www/" . $hlsFolder . "/" . $stream->id . "*");
                }
            }
        }
        
        // ORIGINAL: Update stream fields exactly as before
        $stream->pid = "";
        $stream->running = 0;
        $stream->status = 0;
        $stream->save();
        
        // ORIGINAL: Sleep for 2 seconds
        sleep(2);
        
        return true;
        
    } catch (Exception $e) {
        error_log('Stop stream error: ' . $e->getMessage());
        return false;
    }
}

// ORIGINAL FUNCTION: getTranscode - Keep EXACT same logic and signature
function getTranscode($id, $streamnumber = null)
{
    try {
        $stream = Stream::find($id);
        $setting = Setting::first();
        
        if (!$stream || !$setting) {
            return '';
        }
        
        $trans = $stream->transcode;
        $ffmpeg = $setting->ffmpeg_path;
        $url = $stream->streamurl;
        
        // ORIGINAL: URL selection logic
        if ($streamnumber == 2) {
            $url = $stream->streamurl2;
        }
        if ($streamnumber == 3) {
            $url = $stream->streamurl3;
        }
        
        // ORIGINAL: Build end of ffmpeg command
        $endofffmpeg = "";
        $endofffmpeg .= $stream->bitstreamfilter ? ' -bsf h264_mp4toannexb' : '';
        $endofffmpeg .= ' -hls_flags delete_segments -hls_time 10';
        $endofffmpeg .= ' -hls_list_size 8 /home/fos-streaming/fos/www/' . $setting->hlsfolder . '/' . $stream->id . '_.m3u8  > /dev/null 2>/dev/null & echo $! ';
        
        // ORIGINAL: Check if transcode exists
        if ($trans) {
            // ORIGINAL: Build ffmpeg command with all original parameters
            $ffmpeg .= ' -y';
            $ffmpeg .= ' -probesize ' . ($trans->probesize ? $trans->probesize : '15000000');
            $ffmpeg .= ' -analyzeduration ' . ($trans->analyzeduration ? $trans->analyzeduration : '12000000');
            $ffmpeg .= ' -i ' . '"' . "$url" . '"';
            $ffmpeg .= ' -user_agent "' . ($setting->user_agent ? $setting->user_agent : 'FOS-Streaming') . '"';
            $ffmpeg .= ' -strict -2 -dn ';
            $ffmpeg .= $trans->scale ? ' -vf scale=' . ($trans->scale ? $trans->scale : '') : '';
            $ffmpeg .= $trans->audio_codec ? ' -acodec ' . $trans->audio_codec : '';
            $ffmpeg .= $trans->video_codec ? ' -vcodec ' . $trans->video_codec : '';
            $ffmpeg .= $trans->profile ? ' -profile:v ' . $trans->profile : '';
            $ffmpeg .= $trans->preset ? ' -preset ' . $trans->preset_values : '';
            $ffmpeg .= $trans->video_bitrate ? ' -b:v ' . $trans->video_bitrate . 'k' : '';
            $ffmpeg .= $trans->audio_bitrate ? ' -b:a ' . $trans->audio_bitrate . 'k' : '';
            $ffmpeg .= $trans->fps ? ' -r ' . $trans->fps : '';
            $ffmpeg .= $trans->minrate ? ' -minrate ' . $trans->minrate . 'k' : '';
            $ffmpeg .= $trans->maxrate ? ' -maxrate ' . $trans->maxrate . 'k' : '';
            $ffmpeg .= $trans->bufsize ? ' -bufsize ' . $trans->bufsize . 'k' : '';
            $ffmpeg .= $trans->aspect_ratio ? ' -aspect ' . $trans->aspect_ratio : '';
            $ffmpeg .= $trans->audio_sampling_rate ? ' -ar ' . $trans->audio_sampling_rate : '';
            $ffmpeg .= $trans->crf ? ' -crf ' . $trans->crf : '';
            $ffmpeg .= $trans->audio_channel ? ' -ac ' . $trans->audio_channel : '';
            $ffmpeg .= $stream->bitstreamfilter ? ' -bsf h264_mp4toannexb' : '';
            $ffmpeg .= $trans->threads ? ' -threads ' . $trans->threads : '';
            $ffmpeg .= $trans->deinterlance ? ' -vf yadif' : '';
            $ffmpeg .= $endofffmpeg;
            return $ffmpeg;
        }

        // ORIGINAL: Fallback if no transcode
        $ffmpeg .= ' -probesize 15000000 -analyzeduration 9000000 -i "' . $url . '"';
        $ffmpeg .= ' -user_agent "' . ($setting->user_agent ? $setting->user_agent : 'FOS-Streaming') . '"';
        $ffmpeg .= ' -c copy -c:a aac -b:a 128k';
        $ffmpeg .= $endofffmpeg;
        return $ffmpeg;
        
    } catch (Exception $e) {
        error_log('GetTranscode error: ' . $e->getMessage());
        return '';
    }
}

// ORIGINAL FUNCTION: getTranscodedata - Keep exactly as original
function getTranscodedata($id)
{
    try {
        $trans = Transcode::find($id);
        $setting = Setting::first();
        
        if (!$trans || !$setting) {
            return '';
        }
        
        // ORIGINAL: Build transcode data string exactly as before
        $ffmpeg = "ffmpeg";
        $ffmpeg .= ' -y';
        $ffmpeg .= ' -probesize ' . ($trans->probesize ? $trans->probesize : '15000000');
        $ffmpeg .= ' -analyzeduration ' . ($trans->analyzeduration ? $trans->analyzeduration : '12000000');
        $ffmpeg .= ' -i ' . '"' . "[input]" . '"';
        $ffmpeg .= ' -user_agent "' . ($setting->user_agent ? $setting->user_agent : 'FOS-Streaming') . '"';
        $ffmpeg .= ' -strict -2 -dn ';
        $ffmpeg .= $trans->scale ? ' -vf scale=' . ($trans->scale ? $trans->scale : '') : '';
        $ffmpeg .= $trans->audio_codec ? ' -acodec ' . $trans->audio_codec : '';
        $ffmpeg .= $trans->video_codec ? ' -vcodec ' . $trans->video_codec : '';
        $ffmpeg .= $trans->profile ? ' -profile:v ' . $trans->profile : '';
        $ffmpeg .= $trans->preset ? ' -preset ' . $trans->preset_values : '';
        $ffmpeg .= $trans->video_bitrate ? ' -b:v ' . $trans->video_bitrate . 'k' : '';
        $ffmpeg .= $trans->audio_bitrate ? ' -b:a ' . $trans->audio_bitrate . 'k' : '';
        $ffmpeg .= $trans->fps ? ' -r ' . $trans->fps : '';
        $ffmpeg .= $trans->minrate ? ' -minrate ' . $trans->minrate . 'k' : '';
        $ffmpeg .= $trans->maxrate ? ' -maxrate ' . $trans->maxrate . 'k' : '';
        $ffmpeg .= $trans->bufsize ? ' -bufsize ' . $trans->bufsize . 'k' : '';
        $ffmpeg .= $trans->aspect_ratio ? ' -aspect ' . $trans->aspect_ratio : '';
        $ffmpeg .= $trans->audio_sampling_rate ? ' -ar ' . $trans->audio_sampling_rate : '';
        $ffmpeg .= $trans->crf ? ' -crf ' . $trans->crf : '';
        $ffmpeg .= $trans->audio_channel ? ' -ac ' . $trans->audio_channel : '';
        $ffmpeg .= $trans->threads ? ' -threads ' . $trans->threads : '';
        $ffmpeg .= $trans->deinterlance ? ' -vf yadif' : '';
        $ffmpeg .= " output[HLS]";
        return $ffmpeg;
        
    } catch (Exception $e) {
        error_log('GetTranscodedata error: ' . $e->getMessage());
        return '';
    }
}

// ORIGINAL FUNCTION: start_stream - Keep ALL original logic flow
function start_stream($id)
{
    try {
        $stream = Stream::find($id);
        $setting = Setting::first();
        
        if (!$stream || !$setting) {
            return false;
        }
        
        // ORIGINAL: Check if restream
        if ($stream->restream) {
            $stream->checker = 0;
            $stream->pid = null;
            $stream->running = 1;
            $stream->status = 1;
        } else {
            $stream->checker = 0;
            
            // ORIGINAL: Check stream URL with ffprobe
            $checkstreamurl = shell_exec('' . $setting->ffprobe_path . ' -analyzeduration 1000000 -probesize 9000000 -i "' . $stream->streamurl . '" -v  quiet -print_format json -show_streams 2>&1');
            $streaminfo = json_decode($checkstreamurl, true);
            
            if ($streaminfo) {
                // ORIGINAL: Start transcode and get PID
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
            } else {
                // ORIGINAL: Try backup URLs - EXACT same logic as original
                $stream->running = 1;
                $stream->status = 2;
                if (checkPid($stream->pid)) {
                    shell_exec("kill -9 " . $stream->pid);
                    shell_exec("/bin/rm -r /home/fos-streaming/fos/www/" . $setting->hlsfolder . "/" . $stream->id . "*");
                }

                if ($stream->streamurl2) {
                    $stream->checker = 2;
                    $checkstreamurl = shell_exec('' . $setting->ffprobe_path . ' -analyzeduration 1000000 -probesize 9000000 -i "' . $stream->streamurl2 . '" -v  quiet -print_format json -show_streams 2>&1');
                    $streaminfo = json_decode($checkstreamurl, true);

                    if ($streaminfo) {
                        $pid = shell_exec(getTranscode($stream->id, 2));
                        $stream->pid = $pid;
                        $stream->running = 1;
                        $stream->status = 1;
                        
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
                    } else {
                        $stream->running = 1;
                        $stream->status = 2;
                        if (checkPid($stream->pid)) {
                            shell_exec("kill -9 " . $stream->pid);
                            shell_exec("/bin/rm -r /home/fos-streaming/fos/www/" . $setting->hlsfolder . "/" . $stream->id . "*");
                        }
                        
                        if ($stream->streamurl3) {
                            $stream->checker = 3;
                            $checkstreamurl = shell_exec('' . $setting->ffprobe_path . ' -analyzeduration 1000000 -probesize 9000000 -i "' . $stream->streamurl3 . '" -v  quiet -print_format json -show_streams 2>&1');
                            $streaminfo = json_decode($checkstreamurl, true);
                            
                            if ($streaminfo) {
                                $pid = shell_exec(getTranscode($stream->id, 3));
                                $stream->pid = $pid;
                                $stream->running = 1;
                                $stream->status = 1;

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
                            } else {
                                $stream->running = 1;
                                $stream->status = 2;
                                $stream->pid = null;
                            }
                        }
                    }
                }
            }
        }
        
        $stream->save();
        return true;
        
    } catch (Exception $e) {
        error_log('Start stream error: ' . $e->getMessage());
        return false;
    }
}

// ORIGINAL FUNCTION: generatEginxConfPort - Keep exact same name and logic
function generatEginxConfPort($port)
{
    // ENHANCEMENT: Input validation
    $port = (int)$port;
    if ($port < 1024 || $port > 65535) {
        $port = 8000; // Default fallback
    }
    
    // ORIGINAL: Generate nginx config with exact same format
    ob_start();
    echo 'user  nginx;
worker_processes  auto;
worker_rlimit_nofile 655350;

events {
    worker_connections  65535;
    use epoll;
        accept_mutex on;
        multi_accept on;
}

http {
        include                   mime.types;
        default_type              application/octet-stream;
        sendfile                  on;
        tcp_nopush                on;
        tcp_nodelay               on;
        reset_timedout_connection on;
        gzip                      off;
        fastcgi_read_timeout      200;
        access_log                off;
        keepalive_timeout         10;
        client_max_body_size      999m;
        send_timeout              120s;
        sendfile_max_chunk        512k;
        lingering_close           off;
	server {
		listen ' . $port . ';
		root /home/fos-streaming/fos/www1/;
		server_tokens off;
		chunked_transfer_encoding off;
		rewrite ^/live/(.*)/(.*)/(.*)$ /stream.php?username=$1&password=$2&stream=$3 break;
		location ~ \.php$ {
		  try_files $uri =404;
		  fastcgi_index index.php;
		  include fastcgi_params;
		  fastcgi_buffering on;
		  fastcgi_buffers 96 32k;
		  fastcgi_buffer_size 32k;
		  fastcgi_max_temp_file_size 0;
		  fastcgi_keep_conn on;
		  fastcgi_param SCRIPT_FILENAME /home/fos-streaming/fos/www1/$fastcgi_script_name;
		  fastcgi_param SCRIPT_NAME $fastcgi_script_name;
		  fastcgi_pass 127.0.0.1:9002;
		}	
	}
	server {
		listen 7777;
		root /home/fos-streaming/fos/www/;
                index index.php index.html index.htm;
                server_tokens off;
                chunked_transfer_encoding off;
		location ~ \.php$ {
                        try_files $uri =404;
                        fastcgi_index index.php;
                        include fastcgi_params;
                        fastcgi_buffering on;
                        fastcgi_buffers 96 32k;
                        fastcgi_buffer_size 32k;
                        fastcgi_max_temp_file_size 0;
                        fastcgi_keep_conn on;
                        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                        fastcgi_param SCRIPT_NAME $fastcgi_script_name;
                        fastcgi_pass 127.0.0.1:9002;
		}
	}
}';
    
    $file = '/home/fos-streaming/fos/nginx/conf/nginx.conf';
    $current = ob_get_clean();
    
    // ENHANCEMENT: Safe file writing
    if (is_dir(dirname($file))) {
        file_put_contents($file, $current);
    }
}

// OPTIONAL: Add new security functions only if they don't conflict
if (!function_exists('generateCSRFToken')) {
    function generateCSRFToken()
    {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
}

if (!function_exists('validateCSRFToken')) {
    function validateCSRFToken($token)
    {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
}

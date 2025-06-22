<?php
declare(strict_types=1);

/**
 * Säker Cron-skript för FOS-Streaming
 * PHP 8.1+ kompatibel med förbättrad säkerhet och prestandaoptimering
 */

// Säkerhetskonstanter
define('CRON_VERSION', '2.0.0');
define('MAX_EXECUTION_TIME', 300); // 5 minuter
define('MAX_STREAMS_PER_RUN', 50);
define('STREAM_CHECK_TIMEOUT', 15);
define('MAX_RESTART_ATTEMPTS', 3);
define('PROCESS_CLEANUP_INTERVAL', 3600); // 1 timme

// Sätt exekveringstid och minnesbegränsning
set_time_limit(MAX_EXECUTION_TIME);
ini_set('memory_limit', '256M');

// Endast CLI eller localhost-åtkomst
if (!isCronAccessAllowed()) {
    logSecurityViolation();
    http_response_code(403);
    die('Åtkomst nekad: Endast systemcron eller localhost tillåten');
}

/**
 * Kontrollera om cron-åtkomst är tillåten
 */
function isCronAccessAllowed(): bool
{
    // CLI-läge (föredraget för cron)
    if (php_sapi_name() === 'cli') {
        return true;
    }
    
    // Webb-åtkomst endast från localhost
    if (isset($_SERVER['SERVER_ADDR'], $_SERVER['REMOTE_ADDR'])) {
        $serverAddr = $_SERVER['SERVER_ADDR'];
        $remoteAddr = $_SERVER['REMOTE_ADDR'];
        
        // Tillåt endast localhost-adresser
        $allowedIps = ['127.0.0.1', '::1', $serverAddr];
        
        return in_array($remoteAddr, $allowedIps, true);
    }
    
    return false;
}

/**
 * Logga säkerhetsöverträdelser
 */
function logSecurityViolation(): void
{
    $logData = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'script' => 'cron.php',
        'violation' => 'unauthorized_access_attempt'
    ];
    
    error_log('SECURITY VIOLATION: ' . json_encode($logData));
}

/**
 * Säker loggning av cron-aktiviteter
 */
function cronLog(string $level, string $message, array $context = []): void
{
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'level' => $level,
        'message' => $message,
        'context' => $context,
        'memory_usage' => memory_get_usage(true),
        'peak_memory' => memory_get_peak_usage(true)
    ];
    
    $logLine = sprintf(
        "[%s] %s: %s %s\n",
        $logEntry['timestamp'],
        strtoupper($level),
        $message,
        !empty($context) ? json_encode($context) : ''
    );
    
    // Logga till systemlog och specifik cronlog
    error_log(trim($logLine));
    
    $cronLogFile = '/var/log/fos-streaming/cron.log';
    if (is_writable(dirname($cronLogFile))) {
        file_put_contents($cronLogFile, $logLine, FILE_APPEND | LOCK_EX);
    }
}

/**
 * Säker process-kontroll med validering
 */
function isProcessRunning(int $pid): bool
{
    if ($pid <= 0 || $pid > 4194304) {
        return false;
    }
    
    // Använd proc_open för säkrare kommando-exekvering
    $descriptorspec = [
        0 => ["pipe", "r"],
        1 => ["pipe", "w"], 
        2 => ["pipe", "w"]
    ];
    
    $cmd = 'ps -p ' . escapeshellarg((string)$pid) . ' -o pid=';
    $process = proc_open($cmd, $descriptorspec, $pipes);
    
    if (!is_resource($process)) {
        return false;
    }
    
    fclose($pipes[0]);
    $output = trim(stream_get_contents($pipes[1]));
    fclose($pipes[1]);
    fclose($pipes[2]);
    
    $exitCode = proc_close($process);
    
    return $exitCode === 0 && !empty($output) && (int)$output === $pid;
}

/**
 * Säker terminering av process
 */
function terminateProcess(int $pid): bool
{
    if (!isProcessRunning($pid)) {
        return true;
    }
    
    $descriptorspec = [
        0 => ["pipe", "r"],
        1 => ["pipe", "w"],
        2 => ["pipe", "w"]
    ];
    
    // Först försök med SIGTERM (graceful)
    $process = proc_open('kill -TERM ' . escapeshellarg((string)$pid), $descriptorspec, $pipes);
    if (is_resource($process)) {
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
        
        // Vänta 3 sekunder på graceful shutdown
        sleep(3);
        
        if (!isProcessRunning($pid)) {
            return true;
        }
    }
    
    // Om processen fortfarande körs, använd SIGKILL
    $process = proc_open('kill -KILL ' . escapeshellarg((string)$pid), $descriptorspec, $pipes);
    if (is_resource($process)) {
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
        
        sleep(1);
        return !isProcessRunning($pid);
    }
    
    return false;
}

/**
 * Säker stream-validering med FFprobe
 */
function validateStream(string $streamUrl, string $ffprobePath): array
{
    // Validera URL
    if (!filter_var($streamUrl, FILTER_VALIDATE_URL) && 
        !preg_match('/^[a-zA-Z][a-zA-Z0-9+.-]*:/', $streamUrl)) {
        return ['valid' => false, 'error' => 'Invalid stream URL format'];
    }
    
    // Validera FFprobe-sökväg
    if (!is_executable($ffprobePath)) {
        return ['valid' => false, 'error' => 'FFprobe not executable'];
    }
    
    $descriptorspec = [
        0 => ["pipe", "r"],
        1 => ["pipe", "w"],
        2 => ["pipe", "w"]
    ];
    
    // Bygg säkert FFprobe-kommando
    $cmd = sprintf(
        'timeout %d %s -analyzeduration %d -probesize %d -i %s -v quiet -print_format json -show_streams',
        STREAM_CHECK_TIMEOUT,
        escapeshellcmd($ffprobePath),
        10000000,
        9000000,
        escapeshellarg($streamUrl)
    );
    
    $process = proc_open($cmd, $descriptorspec, $pipes);
    
    if (!is_resource($process)) {
        return ['valid' => false, 'error' => 'Failed to execute FFprobe'];
    }
    
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    $error = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    
    $exitCode = proc_close($process);
    
    if ($exitCode !== 0) {
        return ['valid' => false, 'error' => 'FFprobe failed: ' . $error];
    }
    
    $streamInfo = json_decode($output, true);
    
    if (!$streamInfo || !isset($streamInfo['streams']) || empty($streamInfo['streams'])) {
        return ['valid' => false, 'error' => 'No valid streams found'];
    }
    
    return [
        'valid' => true,
        'streams' => $streamInfo['streams'],
        'format' => $streamInfo['format'] ?? null
    ];
}

/**
 * Säker filrensning för stream
 */
function cleanupStreamFiles(int $streamId, string $hlsFolder): bool
{
    $basePath = '/home/fos-streaming/fos/www/';
    
    // Validera HLS-mapp
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $hlsFolder)) {
        cronLog('error', 'Invalid HLS folder name', ['folder' => $hlsFolder]);
        return false;
    }
    
    $hlsPath = $basePath . $hlsFolder . '/';
    
    // Kontrollera att sökvägen är säker
    $realBasePath = realpath($basePath);
    $realHlsPath = realpath($hlsPath);
    
    if (!$realHlsPath || strpos($realHlsPath, $realBasePath) !== 0) {
        cronLog('error', 'Invalid HLS path detected', ['path' => $hlsPath]);
        return false;
    }
    
    // Hitta och ta bort stream-filer säkert
    $pattern = $hlsPath . $streamId . '*';
    $files = glob($pattern);
    
    $cleanedFiles = 0;
    foreach ($files as $file) {
        $realFile = realpath($file);
        
        // Dubbelkolla att filen är inom tillåtet område
        if ($realFile && strpos($realFile, $realHlsPath) === 0 && is_file($realFile)) {
            if (unlink($realFile)) {
                $cleanedFiles++;
            }
        }
    }
    
    cronLog('info', 'Stream files cleaned', [
        'stream_id' => $streamId,
        'files_removed' => $cleanedFiles
    ]);
    
    return $cleanedFiles > 0;
}

/**
 * Restart stream med säkerhetsvalidering
 */
function restartStream(object $stream, object $setting, int $streamNumber = 1): bool
{
    try {
        // Välj rätt stream URL
        $streamUrl = match($streamNumber) {
            1 => $stream->streamurl,
            2 => $stream->streamurl2,
            3 => $stream->streamurl3,
            default => null
        };
        
        if (empty($streamUrl)) {
            cronLog('warning', 'No stream URL for stream number', [
                'stream_id' => $stream->id,
                'stream_number' => $streamNumber
            ]);
            return false;
        }
        
        // Validera stream
        $validation = validateStream($streamUrl, $setting->ffprobe_path);
        
        if (!$validation['valid']) {
            cronLog('warning', 'Stream validation failed', [
                'stream_id' => $stream->id,
                'stream_number' => $streamNumber,
                'error' => $validation['error']
            ]);
            return false;
        }
        
        // Hämta säkert transcode-kommando
        $transcodeCmd = getTranscode($stream->id, $streamNumber === 1 ? null : $streamNumber);
        
        if (empty($transcodeCmd)) {
            cronLog('error', 'Failed to generate transcode command', [
                'stream_id' => $stream->id,
                'stream_number' => $streamNumber
            ]);
            return false;
        }
        
        // Starta ny process
        $descriptorspec = [
            0 => ["pipe", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];
        
        $process = proc_open($transcodeCmd, $descriptorspec, $pipes);
        
        if (!is_resource($process)) {
            cronLog('error', 'Failed to start transcode process', [
                'stream_id' => $stream->id,
                'stream_number' => $streamNumber
            ]);
            return false;
        }
        
        fclose($pipes[0]);
        $pid = trim(stream_get_contents($pipes[1]));
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
        
        if (!is_numeric($pid) || (int)$pid <= 0) {
            cronLog('error', 'Invalid PID returned', [
                'stream_id' => $stream->id,
                'stream_number' => $streamNumber,
                'pid' => $pid
            ]);
            return false;
        }
        
        // Uppdatera stream
        $stream->pid = (int)$pid;
        $stream->running = 1;
        $stream->status = 1;
        $stream->checker = $streamNumber;
        
        // Extrahera codec-information från validering
        if (isset($validation['streams'])) {
            $video = '';
            $audio = '';
            
            foreach ($validation['streams'] as $streamInfo) {
                if (empty($video) && ($streamInfo['codec_type'] ?? '') === 'video') {
                    $video = $streamInfo['codec_name'] ?? '';
                }
                if (empty($audio) && ($streamInfo['codec_type'] ?? '') === 'audio') {
                    $audio = $streamInfo['codec_name'] ?? '';
                }
            }
            
            $stream->video_codec_name = $video;
            $stream->audio_codec_name = $audio;
        }
        
        cronLog('info', 'Stream restarted successfully', [
            'stream_id' => $stream->id,
            'stream_number' => $streamNumber,
            'pid' => (int)$pid
        ]);
        
        return true;
        
    } catch (Exception $e) {
        cronLog('error', 'Exception during stream restart', [
            'stream_id' => $stream->id,
            'stream_number' => $streamNumber,
            'error' => $e->getMessage()
        ]);
        return false;
    }
}

/**
 * Huvudfunktion för cron-exekvering
 */
function executeCronJob(): void
{
    cronLog('info', 'Cron job started', ['version' => CRON_VERSION]);
    
    try {
        // Ladda konfiguration säkert
        require_once __DIR__ . '/config.php';
        
        $setting = Setting::first();
        if (!$setting) {
            throw new RuntimeException('Settings not found in database');
        }
        
        $processedStreams = 0;
        $restartedStreams = 0;
        $failedStreams = 0;
        
        // Hantera aktiva streams med PID
        $activeStreams = Stream::where('pid', '!=', 0)
                              ->where('running', '=', 1)
                              ->limit(MAX_STREAMS_PER_RUN)
                              ->get();
        
        foreach ($activeStreams as $stream) {
            $processedStreams++;
            
            if (!isProcessRunning((int)$stream->pid)) {
                cronLog('info', 'Stream process not running, attempting restart', [
                    'stream_id' => $stream->id,
                    'old_pid' => $stream->pid
                ]);
                
                $stream->checker = 0;
                
                // Försök restart med primär URL
                if (restartStream($stream, $setting, 1)) {
                    $restartedStreams++;
                } else {
                    // Försök backup URLs om primär misslyckas
                    $restarted = false;
                    
                    if (!empty($stream->streamurl2)) {
                        cronLog('info', 'Trying backup stream 2', ['stream_id' => $stream->id]);
                        if (restartStream($stream, $setting, 2)) {
                            $restartedStreams++;
                            $restarted = true;
                        }
                    }
                    
                    if (!$restarted && !empty($stream->streamurl3)) {
                        cronLog('info', 'Trying backup stream 3', ['stream_id' => $stream->id]);
                        if (restartStream($stream, $setting, 3)) {
                            $restartedStreams++;
                            $restarted = true;
                        }
                    }
                    
                    if (!$restarted) {
                        $stream->running = 1;
                        $stream->status = 2;
                        $stream->pid = null;
                        $failedStreams++;
                        
                        // Rensa gamla filer för misslyckade streams
                        cleanupStreamFiles($stream->id, $setting->hlsfolder);
                        
                        cronLog('warning', 'Failed to restart stream on all URLs', [
                            'stream_id' => $stream->id
                        ]);
                    }
                }
                
                $stream->save();
            }
        }
        
        // Hantera restreams (kontrollera utan att starta om)
        $restreams = Stream::where('restream', '=', 1)
                          ->where('running', '=', 1)
                          ->limit(MAX_STREAMS_PER_RUN)
                          ->get();
        
        foreach ($restreams as $stream) {
            $processedStreams++;
            
            // Kontrollera primär URL
            $validation = validateStream($stream->streamurl, $setting->ffprobe_path);
            
            if ($validation['valid']) {
                $stream->checker = 0;
            } else {
                // Kontrollera backup URLs
                if (!empty($stream->streamurl2)) {
                    $validation2 = validateStream($stream->streamurl2, $setting->ffprobe_path);
                    if ($validation2['valid']) {
                        $stream->checker = 2;
                    } elseif (!empty($stream->streamurl3)) {
                        $validation3 = validateStream($stream->streamurl3, $setting->ffprobe_path);
                        if ($validation3['valid']) {
                            $stream->checker = 3;
                        }
                    }
                }
            }
            
            $stream->save();
        }
        
        cronLog('info', 'Cron job completed successfully', [
            'processed_streams' => $processedStreams,
            'restarted_streams' => $restartedStreams,
            'failed_streams' => $failedStreams,
            'execution_time' => number_format(microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'], 2) . 's'
        ]);
        
    } catch (Exception $e) {
        cronLog('error', 'Cron job failed with exception', [
            'error' => $e->getMessage(),
            'file' => $e->getFile(),
            'line' => $e->getLine()
        ]);
        
        // Skicka notifikation till systemadministratörer
        error_log('CRITICAL: FOS-Streaming cron job failed - ' . $e->getMessage());
    }
}

/**
 * Cleanup för gamla processer och temporära filer
 */
function performMaintenanceCleanup(): void
{
    static $lastCleanup = 0;
    
    if (time() - $lastCleanup < PROCESS_CLEANUP_INTERVAL) {
        return;
    }
    
    cronLog('info', 'Performing maintenance cleanup');
    
    // Rensa gamla rate limiting-filer
    $tempDir = sys_get_temp_dir();
    $rateLimitFiles = glob($tempDir . '/fos_rate_limit_*');
    $cleanedFiles = 0;
    
    foreach ($rateLimitFiles as $file) {
        if (is_file($file) && (time() - filemtime($file)) > 86400) { // 24 timmar
            if (unlink($file)) {
                $cleanedFiles++;
            }
        }
    }
    
    cronLog('info', 'Maintenance cleanup completed', [
        'cleaned_rate_limit_files' => $cleanedFiles
    ]);
    
    $lastCleanup = time();
}

// Huvudexekvering
try {
    // Utför underhållsrengöring
    performMaintenanceCleanup();
    
    // Kör huvudcron-jobbet
    executeCronJob();
    
} catch (Throwable $e) {
    cronLog('critical', 'Fatal error in cron execution', [
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ]);
    
    exit(1);
}

exit(0);

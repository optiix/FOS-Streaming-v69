<?php
declare(strict_types=1);

/**
 * FOS-Streaming Säker Inloggningssida
 * PHP 8.1+ kompatibel med omfattande säkerhetsförbättringar
 */

// Säkerhetshuvuden före all output
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:;');
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

require_once 'config.php';

// Kontrollera om användaren redan är inloggad
if (isset($_SESSION['user_id']) && isset($_SESSION['csrf_token'])) {
    header("Location: dashboard.php", true, 302);
    exit();
}

// Rate limiting baserat på IP
$clientIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// Kontrollera rate limiting
if (!checkRateLimit($clientIP)) {
    $timeLeft = LOCKOUT_TIME - (time() - getLastFailedAttempt($clientIP));
    $error = "För många inloggningsförsök. Försök igen om " . ceil($timeLeft / 60) . " minuter.";
    logSecurityEvent('rate_limit_exceeded', $clientIP);
} else {
    $error = '';

    // Hantera inloggningsförsök
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit'])) {
        
        // CSRF-skydd
        if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
            $error = "Säkerhetsfel. Ladda om sidan och försök igen.";
            logSecurityEvent('csrf_violation', $clientIP);
        } else {
            
            // Validera indata
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';
            
            if (empty($username) || empty($password)) {
                $error = "Användarnamn och lösenord krävs";
                recordFailedLogin($clientIP);
            } else {
                
                // Validera längd och tecken
                if (strlen($username) > 50 || strlen($password) > 100) {
                    $error = "Ogiltiga inloggningsuppgifter";
                    recordFailedLogin($clientIP);
                    logSecurityEvent('invalid_input_length', $clientIP);
                } elseif (!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
                    $error = "Ogiltiga tecken i användarnamn";
                    recordFailedLogin($clientIP);
                    logSecurityEvent('invalid_username_chars', $clientIP);
                } else {
                    
                    // Säker databasförfrågan med prepared statements
                    try {
                        $admin = Admin::where('username', $username)->first();
                        
                        if ($admin && password_verify($password, $admin->password)) {
                            // Lyckad inloggning
                            
                            // Rensa rate limiting för denna IP
                            clearRateLimit($clientIP);
                            
                            // Regenerera session ID för säkerhet
                            session_regenerate_id(true);
                            
                            // Sätt sessionsvariabler
                            $_SESSION['user_id'] = $admin->id;
                            $_SESSION['username'] = $admin->username;
                            $_SESSION['csrf_token'] = generateCSRFToken();
                            $_SESSION['login_time'] = time();
                            $_SESSION['last_activity'] = time();
                            $_SESSION['user_ip'] = $clientIP;
                            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
                            
                            // Uppdatera senaste inloggning i databasen
                            $admin->last_login = date('Y-m-d H:i:s');
                            $admin->last_ip = $clientIP;
                            $admin->save();
                            
                            // Logga lyckad inloggning
                            logSecurityEvent('successful_login', $clientIP, [
                                'username' => $username,
                                'user_id' => $admin->id
                            ]);
                            
                            header("Location: dashboard.php", true, 302);
                            exit();
                            
                        } else {
                            // Misslyckad inloggning
                            $error = "Ogiltiga inloggningsuppgifter";
                            recordFailedLogin($clientIP);
                            
                            logSecurityEvent('failed_login', $clientIP, [
                                'attempted_username' => $username
                            ]);
                            
                            // Lägg till extra fördröjning för att förhindra brute force
                            sleep(2);
                        }
                        
                    } catch (Exception $e) {
                        $error = "Systemfel. Försök igen senare.";
                        logSecurityEvent('database_error', $clientIP, [
                            'error' => $e->getMessage()
                        ]);
                    }
                }
            }
        }
    }
}

// Generera ny CSRF-token för formuläret
$csrfToken = generateCSRFToken();

// Hjälpfunktioner för säkerhet
function getLastFailedAttempt(string $ip): int
{
    $cacheFile = sys_get_temp_dir() . '/fos_rate_limit_' . md5($ip);
    
    if (file_exists($cacheFile)) {
        $data = json_decode(file_get_contents($cacheFile), true);
        return $data['timestamp'] ?? 0;
    }
    
    return 0;
}

function logSecurityEvent(string $event, string $ip, array $context = []): void
{
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event' => $event,
        'ip' => $ip,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'context' => $context
    ];
    
    $logLine = json_encode($logEntry) . "\n";
    
    // Logga till säkerhetslogg
    $securityLog = '/var/log/fos-streaming/security.log';
    if (is_writable(dirname($securityLog))) {
        file_put_contents($securityLog, $logLine, FILE_APPEND | LOCK_EX);
    }
    
    // Logga till systemlog också
    error_log("FOS-STREAMING SECURITY: $event from $ip");
}

// Kontrollera om vi ska visa honeypot (för att fånga bots)
$showHoneypot = rand(1, 100) <= 10; // 10% chans
?>

<!DOCTYPE html>
<html lang="sv">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    
    <title>FOS-Streaming Säker Panel</title>
    
    <!-- Bootstrap core CSS -->
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <link href="fonts/css/font-awesome.min.css" rel="stylesheet">
    <link href="css/animate.min.css" rel="stylesheet">
    <link href="css/custom.css" rel="stylesheet">
    <link href="css/icheck/flat/green.css" rel="stylesheet">
    
    <style>
        .security-notice {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            text-align: center;
            font-size: 12px;
            margin-bottom: 20px;
        }
        
        .login-container {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login-box {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            max-width: 400px;
            width: 100%;
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .login-header h1 {
            color: #2c3e50;
            font-weight: 700;
            margin-bottom: 10px;
        }
        
        .login-header .subtitle {
            color: #7f8c8d;
            font-size: 14px;
        }
        
        .form-control {
            border: 2px solid #ecf0f1;
            border-radius: 5px;
            padding: 12px 15px;
            margin-bottom: 15px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 5px;
            padding: 12px 30px;
            color: white;
            font-weight: 600;
            width: 100%;
            transition: transform 0.2s;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            color: white;
        }
        
        .error-message {
            background: #e74c3c;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            color: #95a5a6;
            font-size: 12px;
        }
        
        .security-badge {
            position: fixed;
            top: 10px;
            right: 10px;
            background: #27ae60;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 10px;
            z-index: 1000;
        }
        
        /* Honeypot för att fånga bots */
        .honeypot {
            position: absolute;
            left: -9999px;
            opacity: 0;
        }
    </style>
</head>

<body>
    <div class="security-badge">
        🔒 Säker Inloggning Aktiv
    </div>
    
    <div class="security-notice">
        🛡️ Denna webbplats använder avancerad säkerhet. All aktivitet loggas och övervakas.
    </div>
    
    <div class="login-container">
        <div class="login-box">
            <div class="login-header">
                <h1>🚀 FOS-Streaming</h1>
                <div class="subtitle">Säker Administrationspanel</div>
            </div>
            
            <?php if (!empty($error)): ?>
                <div class="error-message">
                    <i class="fa fa-exclamation-triangle"></i>
                    <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
                </div>
            <?php endif; ?>
            
            <form action="" method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">
                
                <?php if ($showHoneypot): ?>
                    <!-- Honeypot fält för att fånga bots -->
                    <input type="text" name="email" class="honeypot" tabindex="-1" autocomplete="off">
                    <input type="password" name="confirm_password" class="honeypot" tabindex="-1" autocomplete="off">
                <?php endif; ?>
                
                <div class="form-group">
                    <input type="text" 
                           name="username" 
                           class="form-control" 
                           placeholder="👤 Användarnamn" 
                           required 
                           maxlength="50"
                           pattern="[a-zA-Z0-9_-]+"
                           title="Endast bokstäver, siffror, underscore och bindestreck tillåtna"
                           autocomplete="username">
                </div>
                
                <div class="form-group">
                    <input type="password" 
                           name="password" 
                           class="form-control" 
                           placeholder="🔐 Lösenord" 
                           required 
                           maxlength="100"
                           autocomplete="current-password">
                </div>
                
                <div class="form-group">
                    <button type="submit" name="submit" class="btn btn-login">
                        <i class="fa fa-sign-in"></i> Logga In Säkert
                    </button>
                </div>
            </form>
            
            <div class="footer">
                <p>
                    <i class="fa fa-shield"></i> 
                    &copy; <?= date('Y') ?> FOS-Streaming Säker Version
                    <br>
                    <small>
                        <a href="https://github.com/optiix/FOS-Streaming-v69" target="_blank" style="color: #667eea;">
                            optiix/FOS-Streaming-v69
                        </a>
                    </small>
                </p>
                
                <div style="margin-top: 15px; font-size: 10px; color: #bdc3c7;">
                    🔒 SSL/TLS Kryptering | 🛡️ Rate Limiting | 🚫 CSRF-skydd | 📝 Säkerhetsloggning
                </div>
            </div>
        </div>
    </div>

    <script src="js/jquery.min.js"></script>
    <script>
        // Förhindra multiple submissions
        $(document).ready(function() {
            $('form').on('submit', function() {
                $('button[type="submit"]').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Loggar in...');
            });
            
            // Auto-fokus på användarnamn
            $('input[name="username"]').focus();
            
            // Säkerhetsvarning vid copy/paste av lösenord
            $('input[name="password"]').on('paste', function() {
                console.warn('🔒 Säkerhetsvarning: Undvik att klistra in lösenord från osäkra källor');
            });
        });
        
        // Förhindra högerklick i produktionsmiljö
        <?php if (getConfig('APP_ENV') === 'production'): ?>
        document.addEventListener('contextmenu', function(e) {
            e.preventDefault();
        });
        
        // Förhindra vanliga developer shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.key === 'F12' || 
                (e.ctrlKey && e.shiftKey && e.key === 'I') || 
                (e.ctrlKey && e.shiftKey && e.key === 'C') || 
                (e.ctrlKey && e.key === 'U')) {
                e.preventDefault();
            }
        });
        <?php endif; ?>
    </script>
</body>
</html>

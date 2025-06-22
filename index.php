<?php

/**
 * FOS-Streaming index.php
 * BACKWARD COMPATIBLE - Seamless authentication migration
 * Maintains original behavior while adding security
 */

require_once 'config.php';

// ORIGINAL: Check if already logged in
if (isset($_SESSION['user_id'])) {
    header("location: dashboard.php");
    exit();
}

// Enhanced but compatible error handling
$error = '';
$clientIP = $_SERVER['REMOTE_ADDR'] ?? '';

// Optional rate limiting (only if functions exist)
$rateLimitExceeded = false;
if (function_exists('checkRateLimit') && function_exists('recordFailedLogin')) {
    if (!checkRateLimit($clientIP)) {
        $rateLimitExceeded = true;
        $error = "Too many failed attempts. Please try again later.";
    }
}

// ORIGINAL: Handle form submission
if (isset($_POST['submit']) && !$rateLimitExceeded) {
    
    // Optional CSRF protection (graceful fallback if functions don't exist)
    $csrfValid = true;
    if (function_exists('validateCSRFToken')) {
        if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
            $csrfValid = false;
            $error = "Security error. Please refresh the page and try again.";
        }
    }
    
    if ($csrfValid) {
        // ORIGINAL: Get and sanitize input exactly as before
        $username = isset($_POST['username']) ? stripslashes($_POST['username']) : '';
        $password = isset($_POST['password']) ? stripslashes($_POST['password']) : '';
        
        // ORIGINAL: Basic validation
        if (empty($username) || empty($password)) {
            $error = "Username and password are required";
            
            // Record failed attempt if function exists
            if (function_exists('recordFailedLogin')) {
                recordFailedLogin($clientIP);
            }
        } else {
            
            try {
                // COMPATIBILITY: Support both old and new authentication methods
                
                // Method 1: ORIGINAL MD5 method (for compatibility)
                $userfind = Admin::where('username', '=', $username)
                              ->where('password', '=', md5($password))
                              ->count();
                
                if ($userfind > 0) {
                    // SUCCESSFUL LOGIN with MD5 - maintain original flow
                    $_SESSION['user_id'] = $username; // ORIGINAL: Use username as user_id
                    
                    // MIGRATION: Upgrade password to secure hash automatically
                    try {
                        $admin = Admin::where('username', '=', $username)->first();
                        if ($admin) {
                            $admin->password = password_hash($password, PASSWORD_DEFAULT);
                            $admin->save();
                            
                            // Optional security logging
                            if (function_exists('logSecurityEvent')) {
                                logSecurityEvent('password_migrated', [
                                    'username' => $username,
                                    'method' => 'automatic_login_migration'
                                ]);
                            }
                        }
                    } catch (Exception $e) {
                        // Migration failed, but login still succeeds for compatibility
                        error_log("Password migration failed for $username: " . $e->getMessage());
                    }
                    
                    // Clear any rate limiting on successful login
                    if (function_exists('clearRateLimit')) {
                        clearRateLimit($clientIP);
                    }
                    
                    // ORIGINAL: Redirect to dashboard
                    header("location: dashboard.php");
                    exit();
                    
                } else {
                    // Method 2: Try new secure password method (for already migrated accounts)
                    $admin = Admin::where('username', '=', $username)->first();
                    
                    if ($admin && strlen($admin->password) > 32) {
                        // This looks like a secure hash, try password_verify
                        if (password_verify($password, $admin->password)) {
                            // SUCCESSFUL LOGIN with secure password
                            $_SESSION['user_id'] = $username; // ORIGINAL: Use username as user_id
                            
                            // Clear rate limiting
                            if (function_exists('clearRateLimit')) {
                                clearRateLimit($clientIP);
                            }
                            
                            // Optional security logging
                            if (function_exists('logSecurityEvent')) {
                                logSecurityEvent('successful_login', [
                                    'username' => $username,
                                    'method' => 'secure_password'
                                ]);
                            }
                            
                            header("location: dashboard.php");
                            exit();
                        }
                    }
                    
                    // FAILED LOGIN - original error handling
                    $error = "Invalid username or password";
                    
                    // Record failed attempt
                    if (function_exists('recordFailedLogin')) {
                        recordFailedLogin($clientIP);
                    }
                    
                    // Optional security logging
                    if (function_exists('logSecurityEvent')) {
                        logSecurityEvent('failed_login', [
                            'username' => $username,
                            'ip' => $clientIP
                        ]);
                    }
                    
                    // Add delay to prevent brute force
                    sleep(2);
                }
                
            } catch (Exception $e) {
                $error = "Login system error. Please try again.";
                error_log("Login error: " . $e->getMessage());
                
                if (function_exists('recordFailedLogin')) {
                    recordFailedLogin($clientIP);
                }
            }
        }
    }
}

// Generate CSRF token if function exists
$csrfToken = '';
if (function_exists('generateCSRFToken')) {
    $csrfToken = generateCSRFToken();
}

?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <!-- Meta, title, CSS, favicons, etc. -->
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>FOS-Streaming Panel</title>

    <!-- Bootstrap -->
    <link href="css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="fonts/css/font-awesome.min.css" rel="stylesheet">
    <!-- Animate.css -->
    <link href="css/animate.min.css" rel="stylesheet">

    <!-- Custom Theme Style -->
    <link href="css/custom.css" rel="stylesheet">
    <link href="css/icheck/flat/green.css" rel="stylesheet">
    
    <style>
        .login_wrapper {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login_form {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            max-width: 400px;
            width: 100%;
        }
        
        .login_form h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
            font-weight: 700;
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
        
        .footer {
            text-align: center;
            margin-top: 30px;
            color: #95a5a6;
            font-size: 12px;
        }
    </style>
  </head>

  <body class="login">
    <div class="security-badge">
        🔒 Enhanced Security Active
    </div>
    
    <div class="login_wrapper">
      <div class="animate form login_form">
        <section class="login_content">
          <form action="" method="post">
            <h1>FOS-Streaming Panel</h1>
            
            <?php if (!empty($error)): ?>
                <div class="error-message">
                    <i class="fa fa-exclamation-triangle"></i>
                    <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($csrfToken)): ?>
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">
            <?php endif; ?>
            
            <div>
              <input type="text" 
                     class="form-control" 
                     placeholder="Username" 
                     required="" 
                     name="username"
                     maxlength="50"
                     autocomplete="username" />
            </div>
            <div>
              <input type="password" 
                     class="form-control" 
                     placeholder="Password" 
                     required="" 
                     name="password"
                     maxlength="100"
                     autocomplete="current-password" />
            </div>
            <div>
              <button type="submit" name="submit" class="btn btn-login">
                  <i class="fa fa-sign-in"></i> Log in
              </button>
            </div>

            <div class="clearfix"></div>

            <div class="separator">
              <div class="footer">
                <p>&copy; <?= date('Y') ?> FOS-Streaming. Enhanced Security Version.</p>
                <p>
                    <small>
                        🔒 Secure Authentication | 🛡️ Rate Limiting | 📝 Security Logging
                    </small>
                </p>
              </div>
            </div>
          </form>
        </section>
      </div>
    </div>
    
    <script src="js/jquery.min.js"></script>
    <script>
        // Prevent multiple form submissions
        $(document).ready(function() {
            $('form').on('submit', function() {
                $('button[type="submit"]').prop('disabled', true)
                    .html('<i class="fa fa-spinner fa-spin"></i> Logging in...');
            });
            
            // Focus on username field
            $('input[name="username"]').focus();
        });
    </script>
  </body>
</html>

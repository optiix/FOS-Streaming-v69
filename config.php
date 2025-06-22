<?php
declare(strict_types=1);

/**
 * Säker konfigurationsfil för FOS-Streaming
 * PHP 8.1+ kompatibel med förbättrad säkerhet
 */

// Säkerhetskonstanter
define('CONFIG_VERSION', '2.0.0');
define('MIN_PHP_VERSION', '8.1.0');
define('SESSION_LIFETIME', 1800); // 30 minuter
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 900); // 15 minuter

// Kontrollera PHP-version
if (version_compare(PHP_VERSION, MIN_PHP_VERSION, '<')) {
    die('PHP ' . MIN_PHP_VERSION . ' eller högre krävs. Nuvarande version: ' . PHP_VERSION);
}

// Säker sessionkonfiguration
if (session_status() === PHP_SESSION_NONE) {
    // Säkra sessioninställningar
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_secure', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.gc_maxlifetime', (string)SESSION_LIFETIME);
    ini_set('session.cookie_lifetime', '0');
    ini_set('session.name', 'FOS_SESSID');
    
    // Förhindra session fixation
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    
    session_start();
    
    // Regenerera session ID regelbundet
    if (!isset($_SESSION['created'])) {
        $_SESSION['created'] = time();
    } elseif (time() - $_SESSION['created'] > 300) { // 5 minuter
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
}

// Sätt timezone säkert
$timezone = 'Europe/Stockholm'; // Ändra till din lokala timezone
if (!date_default_timezone_set($timezone)) {
    date_default_timezone_set('UTC'); // Fallback
}

// Ladda miljövariabler säkert
function loadEnvironmentConfig(): array
{
    $envFile = __DIR__ . '/.env';
    $config = [];
    
    // Kontrollera om .env-fil finns
    if (!file_exists($envFile)) {
        throw new RuntimeException('.env fil saknas. Skapa denna fil med dina konfigurationsinställningar.');
    }
    
    // Kontrollera filbehörigheter (ska vara 600)
    $perms = fileperms($envFile) & 0777;
    if ($perms !== 0600) {
        throw new RuntimeException('.env filen måste ha behörigheter 600 (endast ägaren kan läsa/skriva)');
    }
    
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    
    if ($lines === false) {
        throw new RuntimeException('Kunde inte läsa .env fil');
    }
    
    foreach ($lines as $line) {
        // Hoppa över kommentarer
        if (strpos(trim($line), '#') === 0) {
            continue;
        }
        
        // Parse key=value
        if (strpos($line, '=') !== false) {
            [$key, $value] = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value, '"\'');
            
            // Validera nyckeln
            if (preg_match('/^[A-Z_][A-Z0-9_]*$/', $key)) {
                $config[$key] = $value;
                // Sätt också som miljövariabel
                $_ENV[$key] = $value;
            }
        }
    }
    
    return $config;
}

// Validera obligatoriska konfigurationsnycklar
function validateConfig(array $config): void
{
    $required = [
        'DB_HOST',
        'DB_DATABASE', 
        'DB_USERNAME',
        'DB_PASSWORD',
        'APP_KEY',
        'FFMPEG_PATH',
        'FFPROBE_PATH'
    ];
    
    $missing = [];
    foreach ($required as $key) {
        if (!isset($config[$key]) || empty($config[$key])) {
            $missing[] = $key;
        }
    }
    
    if (!empty($missing)) {
        throw new RuntimeException('Saknade obligatoriska konfigurationsnycklar: ' . implode(', ', $missing));
    }
    
    // Validera databasuppgifter
    if (!filter_var($config['DB_HOST'], FILTER_VALIDATE_IP) && 
        !filter_var($config['DB_HOST'], FILTER_VALIDATE_DOMAIN)) {
        if ($config['DB_HOST'] !== 'localhost') {
            throw new RuntimeException('Ogiltig databasvärd: ' . $config['DB_HOST']);
        }
    }
    
    // Validera att FFmpeg-sökvägar existerar
    if (!is_executable($config['FFMPEG_PATH'])) {
        throw new RuntimeException('FFmpeg hittades inte eller är inte körbar: ' . $config['FFMPEG_PATH']);
    }
    
    if (!is_executable($config['FFPROBE_PATH'])) {
        throw new RuntimeException('FFprobe hittades inte eller är inte körbar: ' . $config['FFPROBE_PATH']);
    }
}

// Krypteringsfunktioner
class SecureConfig
{
    private string $key;
    
    public function __construct(string $appKey)
    {
        if (strlen($appKey) < 32) {
            throw new InvalidArgumentException('APP_KEY måste vara minst 32 tecken');
        }
        $this->key = hash('sha256', $appKey, true);
    }
    
    public function encrypt(string $data): string
    {
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv);
        
        if ($encrypted === false) {
            throw new RuntimeException('Kryptering misslyckades');
        }
        
        return base64_encode($iv . $encrypted);
    }
    
    public function decrypt(string $data): string
    {
        $data = base64_decode($data);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $this->key, OPENSSL_RAW_DATA, $iv);
        
        if ($decrypted === false) {
            throw new RuntimeException('Dekryptering misslyckades');
        }
        
        return $decrypted;
    }
}

try {
    // Ladda konfiguration från miljövariabler
    $config = loadEnvironmentConfig();
    
    // Validera konfiguration
    validateConfig($config);
    
    // Skapa säker krypteringsinstans
    $secureConfig = new SecureConfig($config['APP_KEY']);
    
    // Autoloader
    $autoloadPath = __DIR__ . '/vendor/autoload.php';
    if (!file_exists($autoloadPath)) {
        throw new RuntimeException('Composer autoloader saknas. Kör: composer install');
    }
    require $autoloadPath;
    
    // Säker inkludering av funktioner
    $functionsPath = __DIR__ . '/functions.php';
    if (!file_exists($functionsPath)) {
        throw new RuntimeException('functions.php saknas');
    }
    require_once $functionsPath;
    
    // Importera nödvändiga klasser
    use Philo\Blade\Blade;
    use Illuminate\Database\Capsule\Manager as Capsule;
    
    // Konfigurera Blade template engine säkert
    $views = realpath(__DIR__ . '/views');
    $cache = realpath(__DIR__ . '/cache');
    
    if (!$views || !is_dir($views)) {
        throw new RuntimeException('Views-mappen saknas eller är inte tillgänglig');
    }
    
    if (!$cache || !is_dir($cache)) {
        throw new RuntimeException('Cache-mappen saknas eller är inte tillgänglig');
    }
    
    // Kontrollera skrivbehörigheter för cache
    if (!is_writable($cache)) {
        throw new RuntimeException('Cache-mappen är inte skrivbar');
    }
    
    $template = new Blade($views, $cache);
    
    // Säker databasanslutning med retry-logik
    $capsule = new Capsule;
    
    $dbConfig = [
        'driver'    => 'mysql',
        'host'      => $config['DB_HOST'],
        'database'  => $config['DB_DATABASE'],
        'username'  => $config['DB_USERNAME'],
        'password'  => $config['DB_PASSWORD'],
        'charset'   => 'utf8mb4',
        'collation' => 'utf8mb4_unicode_ci',
        'prefix'    => $config['DB_PREFIX'] ?? '',
        'strict'    => true,
        'options'   => [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
            PDO::ATTR_TIMEOUT => 10
        ]
    ];
    
    $capsule->addConnection($dbConfig);
    $capsule->setAsGlobal();
    $capsule->bootEloquent();
    
    // Testa databasanslutning
    $maxRetries = 3;
    $retryCount = 0;
    
    while ($retryCount < $maxRetries) {
        try {
            $capsule->getConnection()->getPdo();
            break; // Anslutning lyckades
        } catch (Exception $e) {
            $retryCount++;
            
            if ($retryCount >= $maxRetries) {
                throw new RuntimeException('Databasanslutning misslyckades efter ' . $maxRetries . ' försök: ' . $e->getMessage());
            }
            
            // Vänta lite innan nästa försök
            sleep(1);
        }
    }
    
    // Sätt globala variabler för applikationen
    define('APP_KEY', $config['APP_KEY']);
    define('FFMPEG_PATH', $config['FFMPEG_PATH']);
    define('FFPROBE_PATH', $config['FFPROBE_PATH']);
    define('HLS_FOLDER', $config['HLS_FOLDER'] ?? 'hls');
    define('USER_AGENT', $config['USER_AGENT'] ?? 'FOS-Streaming-Secure/2.0');
    
    // CSP och säkerhetshuvuden
    if (!headers_sent()) {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        
        $csp = "default-src 'self'; " .
               "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " .
               "style-src 'self' 'unsafe-inline'; " .
               "img-src 'self' data: https:; " .
               "font-src 'self'; " .
               "connect-src 'self'; " .
               "media-src 'self' blob:; " .
               "object-src 'none'; " .
               "base-uri 'self'; " .
               "form-action 'self';";
        
        header("Content-Security-Policy: $csp");
    }
    
    // Loggning av framgångsrik konfiguration
    error_log('FOS-Streaming konfiguration laddad framgångsrikt - Version: ' . CONFIG_VERSION);
    
} catch (Exception $e) {
    // Säker felhantering utan att avslöja känslig information
    error_log('Konfigurationsfel: ' . $e->getMessage());
    
    // I produktionsmiljö, visa generiskt felmeddelande
    if (isset($config['APP_ENV']) && $config['APP_ENV'] === 'production') {
        die('Systemkonfigurationsfel. Kontakta administratör.');
    } else {
        // I utvecklingsmiljö, visa detaljerat fel
        die('Konfigurationsfel: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
    }
}

// Hjälpfunktioner för konfiguration
function getConfig(string $key, mixed $default = null): mixed
{
    return $_ENV[$key] ?? $default;
}

function isProduction(): bool
{
    return (getConfig('APP_ENV') === 'production');
}

function isDebugMode(): bool
{
    return (getConfig('APP_DEBUG', 'false') === 'true') && !isProduction();
}

// Rate limiting för inloggningsförsök
function checkRateLimit(string $ip): bool
{
    $cacheFile = sys_get_temp_dir() . '/fos_rate_limit_' . md5($ip);
    
    if (file_exists($cacheFile)) {
        $data = json_decode(file_get_contents($cacheFile), true);
        
        if ($data && isset($data['attempts'], $data['timestamp'])) {
            // Återställ räknaren efter lockout-tiden
            if (time() - $data['timestamp'] > LOCKOUT_TIME) {
                unlink($cacheFile);
                return true;
            }
            
            // Kontrollera om max försök uppnåtts
            if ($data['attempts'] >= MAX_LOGIN_ATTEMPTS) {
                return false;
            }
        }
    }
    
    return true;
}

function recordFailedLogin(string $ip): void
{
    $cacheFile = sys_get_temp_dir() . '/fos_rate_limit_' . md5($ip);
    $attempts = 1;
    
    if (file_exists($cacheFile)) {
        $data = json_decode(file_get_contents($cacheFile), true);
        if ($data && isset($data['attempts'])) {
            $attempts = $data['attempts'] + 1;
        }
    }
    
    $data = [
        'attempts' => $attempts,
        'timestamp' => time()
    ];
    
    file_put_contents($cacheFile, json_encode($data), LOCK_EX);
}

function clearRateLimit(string $ip): void
{
    $cacheFile = sys_get_temp_dir() . '/fos_rate_limit_' . md5($ip);
    if (file_exists($cacheFile)) {
        unlink($cacheFile);
    }
}

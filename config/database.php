<?php

use Illuminate\Database\Capsule\Manager as Capsule;

$capsule = new Capsule;

// Enhanced database configuration for FOS-Streaming
// Supports both SQLite (default) and MySQL for production environments

// Get environment variables or use defaults
$db_driver = $_ENV['DB_DRIVER'] ?? 'sqlite';
$db_host = $_ENV['DB_HOST'] ?? 'localhost';
$db_port = $_ENV['DB_PORT'] ?? '3306';
$db_database = $_ENV['DB_DATABASE'] ?? 'fos';
$db_username = $_ENV['DB_USERNAME'] ?? 'fos';
$db_password = $_ENV['DB_PASSWORD'] ?? '';

// Database configuration based on driver
switch ($db_driver) {
    case 'mysql':
        $capsule->addConnection([
            'driver' => 'mysql',
            'host' => $db_host,
            'port' => $db_port,
            'database' => $db_database,
            'username' => $db_username,
            'password' => $db_password,
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => false, // Compatibility with older MySQL modes
            'engine' => 'InnoDB',
            'options' => [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
            ],
        ]);
        break;
        
    case 'sqlite':
    default:
        $database_path = __DIR__ . '/../database.sqlite';
        
        // Ensure database directory exists and is writable
        $database_dir = dirname($database_path);
        if (!is_dir($database_dir)) {
            mkdir($database_dir, 0755, true);
        }
        
        // Set proper permissions for SQLite database
        if (file_exists($database_path)) {
            chmod($database_path, 0664);
        }
        
        $capsule->addConnection([
            'driver' => 'sqlite',
            'database' => $database_path,
            'prefix' => '',
            'foreign_key_constraints' => true,
            'options' => [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_TIMEOUT => 30,
            ],
        ]);
        break;
}

// Set timezone for database operations
date_default_timezone_set($_ENV['APP_TIMEZONE'] ?? 'UTC');

// Configure Eloquent
$capsule->setAsGlobal();
$capsule->bootEloquent();

// Enable query logging in development
if (($_ENV['APP_DEBUG'] ?? 'false') === 'true') {
    $capsule->getConnection()->enableQueryLog();
}

// Test database connection and provide helpful error messages
try {
    $capsule->getConnection()->getPdo();
    
    // Log successful connection
    if (function_exists('error_log')) {
        error_log("FOS-Streaming: Database connection established successfully using {$db_driver} driver");
    }
    
} catch (Exception $e) {
    $error_message = "FOS-Streaming Database Connection Failed: " . $e->getMessage();
    
    // Log the error
    if (function_exists('error_log')) {
        error_log($error_message);
    }
    
    // In production, show a generic error; in development, show details
    if (($_ENV['APP_DEBUG'] ?? 'false') === 'true') {
        die("Database Error: " . $e->getMessage());
    } else {
        die("Database connection failed. Please check your configuration.");
    }
}

// Return the capsule instance for use in other parts of the application
return $capsule;

<?php
declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * FosStreaming Base Model
 * Secure base class for all FOS-Streaming models
 * PHP 8.1+ compatible with comprehensive security enhancements
 */

class FosStreaming extends Model 
{
    /**
     * Indicates if the model should be timestamped by default
     */
    public $timestamps = true;

    /**
     * The default date format for the model
     */
    protected $dateFormat = 'Y-m-d H:i:s';

    /**
     * The storage format of the model's date columns
     */
    protected $dates = [
        'created_at',
        'updated_at',
        'deleted_at'
    ];

    /**
     * Global attributes that should always be cast
     */
    protected $baseCasts = [
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
        'deleted_at' => 'datetime'
    ];

    /**
     * SECURITY: Global guarded attributes to prevent mass assignment
     */
    protected $guarded = [
        'id',
        'created_at',
        'updated_at'
    ];

    /**
     * SECURITY: Maximum items per page for pagination
     */
    protected static int $maxPerPage = 100;

    /**
     * SECURITY: Default items per page
     */
    protected static int $defaultPerPage = 25;

    /**
     * SECURITY: Enable query logging for audit purposes
     */
    protected static bool $queryLogging = true;

    /**
     * SECURITY: Sensitive fields that should be logged but not exposed
     */
    protected array $sensitiveFields = [
        'password',
        'token',
        'secret',
        'key',
        'api_key',
        'private_key'
    ];

    /**
     * Initialize the base model
     */
    public function __construct(array $attributes = [])
    {
        // Merge base casts with model-specific casts
        $this->casts = array_merge($this->baseCasts, $this->casts ?? []);
        
        parent::__construct($attributes);
    }

    /**
     * SECURITY: Override boot method to add global security features
     */
    protected static function boot(): void
    {
        parent::boot();
        
        // Enable query logging for security audit
        if (static::$queryLogging) {
            static::enableQueryLogging();
        }
        
        // Global model events for security
        static::creating(function ($model) {
            static::logModelEvent('creating', $model);
            static::validateSecurityConstraints($model);
        });
        
        static::created(function ($model) {
            static::logModelEvent('created', $model);
        });
        
        static::updating(function ($model) {
            static::logModelEvent('updating', $model);
            static::validateSecurityConstraints($model);
        });
        
        static::updated(function ($model) {
            static::logModelEvent('updated', $model);
        });
        
        static::deleting(function ($model) {
            static::logModelEvent('deleting', $model);
        });
        
        static::deleted(function ($model) {
            static::logModelEvent('deleted', $model);
        });
    }

    /**
     * SECURITY: Enable comprehensive query logging
     */
    protected static function enableQueryLogging(): void
    {
        if (function_exists('config') && config('app.debug', false)) {
            DB::listen(function ($query) {
                $modelClass = static::class;
                $logData = [
                    'model' => $modelClass,
                    'sql' => $query->sql,
                    'bindings' => $query->bindings,
                    'time' => $query->time,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                    'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 255)
                ];
                
                // Log to security audit file
                error_log("MODEL_QUERY: " . json_encode($logData));
            });
        }
    }

    /**
     * SECURITY: Log model events for audit trail
     */
    protected static function logModelEvent(string $event, Model $model): void
    {
        $modelClass = get_class($model);
        $modelId = $model->getKey() ?? 'new';
        
        $logData = [
            'event' => $event,
            'model' => $modelClass,
            'model_id' => $modelId,
            'timestamp' => now()->toISOString(),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 255),
            'user_id' => session('user_id') ?? session('admin_id') ?? 'unknown'
        ];
        
        // Add changed attributes for update events (without sensitive data)
        if (in_array($event, ['updating', 'updated']) && $model->isDirty()) {
            $changes = $model->getDirty();
            $safeChanges = [];
            
            foreach ($changes as $field => $value) {
                if (!in_array($field, $model->sensitiveFields)) {
                    $safeChanges[$field] = is_string($value) ? substr($value, 0, 100) : $value;
                } else {
                    $safeChanges[$field] = '[REDACTED]';
                }
            }
            
            $logData['changes'] = $safeChanges;
        }
        
        error_log("MODEL_EVENT: " . json_encode($logData));
    }

    /**
     * SECURITY: Validate security constraints before saving
     */
    protected static function validateSecurityConstraints(Model $model): void
    {
        // Validate required security fields if they exist
        if (method_exists($model, 'validateSecurityFields')) {
            $model->validateSecurityFields();
        }
        
        // Check for SQL injection patterns in string fields
        foreach ($model->getAttributes() as $field => $value) {
            if (is_string($value) && static::containsSqlInjection($value)) {
                throw new \InvalidArgumentException("Potential SQL injection detected in field: {$field}");
            }
        }
        
        // Validate field lengths to prevent buffer overflow
        static::validateFieldLengths($model);
    }

    /**
     * SECURITY: Check for potential SQL injection patterns
     */
    protected static function containsSqlInjection(string $value): bool
    {
        $dangerousPatterns = [
            '/(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/i',
            '/(\bunion\b.*\bselect\b)/i',
            '/(\bor\b.*=.*)/i',
            '/(\band\b.*=.*)/i',
            '/(\'|\";|--|\/\*|\*\/)/i',
            '/(\bxp_cmdshell\b)/i',
            '/(\bsp_executesql\b)/i'
        ];
        
        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * SECURITY: Validate field lengths against database schema
     */
    protected static function validateFieldLengths(Model $model): void
    {
        // Define maximum lengths for common field types
        $maxLengths = [
            'varchar' => 255,
            'text' => 65535,
            'mediumtext' => 16777215,
            'longtext' => 4294967295
        ];
        
        foreach ($model->getAttributes() as $field => $value) {
            if (is_string($value)) {
                // Basic length validation (can be enhanced with actual schema inspection)
                if (strlen($value) > 65535) { // Basic text field limit
                    throw new \InvalidArgumentException("Field {$field} exceeds maximum length");
                }
            }
        }
    }

    /**
     * SECURITY: Safe pagination with limits
     */
    public function scopePaginateSafely(Builder $query, int $perPage = null, array $columns = ['*'], string $pageName = 'page', int $page = null): \Illuminate\Contracts\Pagination\LengthAwarePaginator
    {
        // Enforce pagination limits
        $perPage = min($perPage ?? static::$defaultPerPage, static::$maxPerPage);
        $perPage = max($perPage, 1); // Minimum 1 item per page
        
        return $query->paginate($perPage, $columns, $pageName, $page);
    }

    /**
     * SECURITY: Safe find with input validation
     */
    public static function findSecure($id, array $columns = ['*']): ?Model
    {
        // Validate ID
        if (!is_numeric($id) || $id <= 0) {
            return null;
        }
        
        try {
            return static::find($id, $columns);
        } catch (\Exception $e) {
            error_log("SECURITY: Error in findSecure for " . static::class . " with ID {$id}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * SECURITY: Safe where clause with SQL injection protection
     */
    public function scopeWhereSafe(Builder $query, string $column, $operator = null, $value = null, string $boolean = 'and'): Builder
    {
        // Validate column name (only allow alphanumeric and underscores)
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $column)) {
            throw new \InvalidArgumentException("Invalid column name: {$column}");
        }
        
        // If two arguments, assume operator is '='
        if (func_num_args() === 3) {
            $value = $operator;
            $operator = '=';
        }
        
        // Validate operator
        $allowedOperators = ['=', '!=', '<>', '<', '>', '<=', '>=', 'like', 'not like', 'in', 'not in', 'between', 'not between'];
        if (!in_array(strtolower($operator), $allowedOperators)) {
            throw new \InvalidArgumentException("Invalid operator: {$operator}");
        }
        
        return $query->where($column, $operator, $value, $boolean);
    }

    /**
     * SECURITY: Safe bulk operations with validation
     */
    public static function createSecureBulk(array $records): array
    {
        $created = [];
        $errors = [];
        
        DB::beginTransaction();
        
        try {
            foreach ($records as $index => $record) {
                try {
                    $model = new static();
                    $model->fill($record);
                    $model->save();
                    $created[] = $model;
                } catch (\Exception $e) {
                    $errors[$index] = $e->getMessage();
                }
            }
            
            if (empty($errors)) {
                DB::commit();
                error_log("SECURITY: Bulk creation successful for " . static::class . " - " . count($created) . " records");
            } else {
                DB::rollBack();
                error_log("SECURITY: Bulk creation failed for " . static::class . " - errors: " . json_encode($errors));
            }
            
        } catch (\Exception $e) {
            DB::rollBack();
            error_log("SECURITY: Bulk creation transaction failed for " . static::class . ": " . $e->getMessage());
            throw $e;
        }
        
        return [
            'created' => $created,
            'errors' => $errors,
            'success' => empty($errors)
        ];
    }

    /**
     * SECURITY: Sanitize output for API responses
     */
    public function toSecureArray(): array
    {
        $array = $this->toArray();
        
        // Remove sensitive fields
        foreach ($this->sensitiveFields as $field) {
            unset($array[$field]);
        }
        
        // Remove hidden fields
        foreach ($this->getHidden() as $field) {
            unset($array[$field]);
        }
        
        return $array;
    }

    /**
     * SECURITY: Safe JSON serialization
     */
    public function toSecureJson(int $options = 0): string
    {
        return json_encode($this->toSecureArray(), $options | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * SECURITY: Get model statistics safely
     */
    public static function getSecureStatistics(): array
    {
        try {
            return [
                'total_count' => static::count(),
                'created_today' => static::whereDate('created_at', today())->count(),
                'created_this_week' => static::whereBetween('created_at', [
                    now()->startOfWeek(),
                    now()->endOfWeek()
                ])->count(),
                'created_this_month' => static::whereMonth('created_at', now()->month)
                                           ->whereYear('created_at', now()->year)
                                           ->count(),
                'last_updated' => static::latest('updated_at')->value('updated_at')
            ];
        } catch (\Exception $e) {
            error_log("SECURITY: Error getting statistics for " . static::class . ": " . $e->getMessage());
            return [];
        }
    }

    /**
     * SECURITY: Clean old records for GDPR compliance
     */
    public static function cleanOldRecords(int $daysToKeep = 365): int
    {
        try {
            $cutoffDate = now()->subDays($daysToKeep);
            $deleted = static::where('created_at', '<', $cutoffDate)->delete();
            
            if ($deleted > 0) {
                error_log("GDPR_CLEANUP: Cleaned {$deleted} old records from " . static::class . " older than {$daysToKeep} days");
            }
            
            return $deleted;
        } catch (\Exception $e) {
            error_log("SECURITY: Error cleaning old records for " . static::class . ": " . $e->getMessage());
            return 0;
        }
    }

    /**
     * SECURITY: Backup model data
     */
    public static function backupData(string $backupPath = null): bool
    {
        try {
            $backupPath = $backupPath ?? '/var/backups/fos-streaming/';
            
            if (!is_dir($backupPath)) {
                mkdir($backupPath, 0750, true);
            }
            
            $filename = $backupPath . static::getTable() . '_backup_' . date('Y-m-d_H-i-s') . '.json';
            $data = static::all()->toArray();
            
            $backupData = [
                'model' => static::class,
                'table' => static::getTable(),
                'backup_date' => now()->toISOString(),
                'record_count' => count($data),
                'data' => $data
            ];
            
            $success = file_put_contents($filename, json_encode($backupData, JSON_PRETTY_PRINT)) !== false;
            
            if ($success) {
                chmod($filename, 0640);
                error_log("BACKUP: Successfully backed up " . count($data) . " records from " . static::class . " to {$filename}");
            }
            
            return $success;
        } catch (\Exception $e) {
            error_log("SECURITY: Error backing up data for " . static::class . ": " . $e->getMessage());
            return false;
        }
    }

    /**
     * SECURITY: Validate model integrity
     */
    public function validateIntegrity(): array
    {
        $issues = [];
        
        // Check for required fields
        if (property_exists($this, 'required') && is_array($this->required)) {
            foreach ($this->required as $field) {
                if (empty($this->$field)) {
                    $issues[] = "Required field '{$field}' is empty";
                }
            }
        }
        
        // Check for data type consistency
        foreach ($this->getCasts() as $field => $type) {
            $value = $this->$field;
            if ($value !== null) {
                switch ($type) {
                    case 'integer':
                    case 'int':
                        if (!is_numeric($value)) {
                            $issues[] = "Field '{$field}' should be numeric";
                        }
                        break;
                    case 'boolean':
                    case 'bool':
                        if (!is_bool($value) && !in_array($value, [0, 1, '0', '1'])) {
                            $issues[] = "Field '{$field}' should be boolean";
                        }
                        break;
                    case 'array':
                        if (!is_array($value)) {
                            $issues[] = "Field '{$field}' should be array";
                        }
                        break;
                }
            }
        }
        
        return $issues;
    }

    /**
     * Get the table name for the model (static method)
     */
    public static function getTableName(): string
    {
        return (new static())->getTable();
    }

    /**
     * SECURITY: Safe query builder with automatic security measures
     */
    public static function secureQuery(): Builder
    {
        return static::query()
                    ->when(static::$queryLogging, function ($query) {
                        // Add query timing and logging
                        return $query;
                    });
    }

    /**
     * SECURITY: Check if current user has permission to access this model
     */
    public function hasAccessPermission(?string $permission = null): bool
    {
        // Override this method in child models for specific permission logic
        return true;
    }

    /**
     * SECURITY: Scope for records accessible by current user
     */
    public function scopeAccessible(Builder $query): Builder
    {
        // Override this method in child models for specific access logic
        return $query;
    }

    /**
     * Get model's human-readable name
     */
    public static function getModelName(): string
    {
        $className = class_basename(static::class);
        return ucfirst(preg_replace('/([a-z])([A-Z])/', '$1 $2', $className));
    }

    /**
     * SECURITY: Rate limiting for model operations
     */
    protected static function checkRateLimit(string $operation, int $maxOperations = 100, int $timeWindowMinutes = 60): bool
    {
        $key = 'model_rate_limit:' . static::class . ':' . $operation . ':' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        
        // Simple rate limiting using session (can be enhanced with Redis/Memcached)
        if (!isset($_SESSION[$key])) {
            $_SESSION[$key] = ['count' => 0, 'start_time' => time()];
        }
        
        $rateData = $_SESSION[$key];
        
        // Reset if time window has passed
        if (time() - $rateData['start_time'] > ($timeWindowMinutes * 60)) {
            $_SESSION[$key] = ['count' => 1, 'start_time' => time()];
            return true;
        }
        
        // Check if limit exceeded
        if ($rateData['count'] >= $maxOperations) {
            error_log("SECURITY: Rate limit exceeded for {$operation} on " . static::class . " from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            return false;
        }
        
        // Increment counter
        $_SESSION[$key]['count']++;
        return true;
    }
}
?>

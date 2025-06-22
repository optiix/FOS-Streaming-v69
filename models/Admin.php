<?php
declare(strict_types=1);

/**
 * Admin Model
 * FOS-Streaming Secure Admin Management
 * PHP 8.1+ compatible with comprehensive security enhancements
 */

class Admin extends FosStreaming 
{
    /**
     * The table associated with the model
     */
    protected $table = 'admins';

    /**
     * The primary key for the model
     */
    protected $primaryKey = 'id';

    /**
     * Indicates if the model should be timestamped
     */
    public $timestamps = true;

    /**
     * The attributes that are mass assignable
     */
    protected $fillable = [
        'username',
        'email',
        'first_name',
        'last_name',
        'role',
        'permissions',
        'active',
        'last_login_at',
        'last_login_ip',
        'failed_login_attempts',
        'locked_until',
        'two_factor_enabled',
        'two_factor_secret',
        'email_verified_at'
    ];

    /**
     * The attributes that should be hidden for serialization
     */
    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_secret',
        'password_reset_token',
        'email_verification_token'
    ];

    /**
     * The attributes that should be cast to native types
     */
    protected $casts = [
        'active' => 'boolean',
        'permissions' => 'array',
        'last_login_at' => 'datetime',
        'locked_until' => 'datetime',
        'email_verified_at' => 'datetime',
        'two_factor_enabled' => 'boolean',
        'failed_login_attempts' => 'integer',
        'created_at' => 'datetime',
        'updated_at' => 'datetime'
    ];

    /**
     * Admin roles
     */
    public const ROLE_SUPER_ADMIN = 'super_admin';
    public const ROLE_ADMIN = 'admin';
    public const ROLE_MODERATOR = 'moderator';
    public const ROLE_SUPPORT = 'support';

    /**
     * Available permissions
     */
    public const PERMISSIONS = [
        'users.view',
        'users.create',
        'users.edit',
        'users.delete',
        'streams.view',
        'streams.create',
        'streams.edit',
        'streams.delete',
        'categories.view',
        'categories.create',
        'categories.edit',
        'categories.delete',
        'settings.view',
        'settings.edit',
        'logs.view',
        'reports.view',
        'system.restart',
        'system.backup',
        'admins.view',
        'admins.create',
        'admins.edit',
        'admins.delete'
    ];

    /**
     * Validation rules for admin data
     */
    public static function validationRules(): array
    {
        return [
            'username' => 'required|string|min:3|max:50|regex:/^[a-zA-Z0-9_-]+$/',
            'email' => 'required|email|max:255',
            'first_name' => 'required|string|max:100',
            'last_name' => 'required|string|max:100',
            'password' => 'required|string|min:8|max:255',
            'role' => 'required|string|in:' . implode(',', [
                self::ROLE_SUPER_ADMIN,
                self::ROLE_ADMIN,
                self::ROLE_MODERATOR,
                self::ROLE_SUPPORT
            ]),
            'permissions' => 'nullable|array',
            'active' => 'boolean',
            'two_factor_enabled' => 'boolean'
        ];
    }

    /**
     * SECURITY: Sanitize input data before saving
     */
    protected function sanitizeInput(array $data): array
    {
        $sanitized = [];
        
        foreach ($data as $key => $value) {
            switch ($key) {
                case 'username':
                    // Only alphanumeric, underscore, and dash
                    $sanitized[$key] = preg_replace('/[^a-zA-Z0-9_-]/', '', trim($value));
                    break;
                    
                case 'email':
                    $sanitized[$key] = filter_var(trim($value), FILTER_SANITIZE_EMAIL);
                    break;
                    
                case 'first_name':
                case 'last_name':
                    $sanitized[$key] = htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8');
                    break;
                    
                case 'role':
                    $sanitized[$key] = in_array($value, [
                        self::ROLE_SUPER_ADMIN,
                        self::ROLE_ADMIN,
                        self::ROLE_MODERATOR,
                        self::ROLE_SUPPORT
                    ]) ? $value : self::ROLE_SUPPORT;
                    break;
                    
                case 'permissions':
                    if (is_array($value)) {
                        $sanitized[$key] = array_intersect($value, self::PERMISSIONS);
                    }
                    break;
                    
                case 'active':
                case 'two_factor_enabled':
                    $sanitized[$key] = (bool)$value;
                    break;
                    
                case 'last_login_ip':
                    $sanitized[$key] = filter_var($value, FILTER_VALIDATE_IP) ?: null;
                    break;
                    
                case 'failed_login_attempts':
                    $sanitized[$key] = max(0, (int)$value);
                    break;
                    
                case 'password':
                    // Don't sanitize password, just validate it
                    $sanitized[$key] = $value;
                    break;
                    
                default:
                    // Skip unknown fields for security
                    continue 2;
            }
        }
        
        return $sanitized;
    }

    /**
     * SECURITY: Override fill method to sanitize input
     */
    public function fill(array $attributes): self
    {
        $sanitized = $this->sanitizeInput($attributes);
        return parent::fill($sanitized);
    }

    /**
     * SECURITY: Hash password when setting
     */
    public function setPasswordAttribute(string $value): void
    {
        if (strlen($value) < 8) {
            throw new InvalidArgumentException('Password must be at least 8 characters long');
        }
        
        // Use PHP 8.1 compatible password hashing
        $this->attributes['password'] = password_hash($value, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3,
        ]);
    }

    /**
     * SECURITY: Verify password
     */
    public function verifyPassword(string $password): bool
    {
        if (empty($this->password)) {
            return false;
        }
        
        return password_verify($password, $this->password);
    }

    /**
     * SECURITY: Check if admin has specific permission
     */
    public function hasPermission(string $permission): bool
    {
        // Super admin has all permissions
        if ($this->role === self::ROLE_SUPER_ADMIN) {
            return true;
        }
        
        // Check if permission exists in the permissions array
        $permissions = $this->permissions ?? [];
        return in_array($permission, $permissions);
    }

    /**
     * SECURITY: Check if admin has any of the given permissions
     */
    public function hasAnyPermission(array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if ($this->hasPermission($permission)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * SECURITY: Check if admin account is locked
     */
    public function isLocked(): bool
    {
        return $this->locked_until && $this->locked_until->isFuture();
    }

    /**
     * SECURITY: Lock admin account
     */
    public function lockAccount(int $minutes = 30): void
    {
        $this->locked_until = now()->addMinutes($minutes);
        $this->save();
        
        error_log("SECURITY: Admin account locked - ID: {$this->id}, Username: {$this->username}");
    }

    /**
     * SECURITY: Unlock admin account
     */
    public function unlockAccount(): void
    {
        $this->locked_until = null;
        $this->failed_login_attempts = 0;
        $this->save();
        
        error_log("SECURITY: Admin account unlocked - ID: {$this->id}, Username: {$this->username}");
    }

    /**
     * SECURITY: Record failed login attempt
     */
    public function recordFailedLogin(string $ipAddress): void
    {
        $this->failed_login_attempts = ($this->failed_login_attempts ?? 0) + 1;
        
        // Lock account after 5 failed attempts
        if ($this->failed_login_attempts >= 5) {
            $this->lockAccount(60); // Lock for 1 hour
        }
        
        $this->save();
        
        error_log("SECURITY: Failed login attempt - Admin ID: {$this->id}, Username: {$this->username}, IP: {$ipAddress}, Attempts: {$this->failed_login_attempts}");
    }

    /**
     * SECURITY: Record successful login
     */
    public function recordSuccessfulLogin(string $ipAddress): void
    {
        $this->last_login_at = now();
        $this->last_login_ip = $ipAddress;
        $this->failed_login_attempts = 0;
        $this->locked_until = null;
        $this->save();
        
        error_log("SECURITY: Successful login - Admin ID: {$this->id}, Username: {$this->username}, IP: {$ipAddress}");
    }

    /**
     * SECURITY: Get default permissions for role
     */
    public static function getDefaultPermissionsForRole(string $role): array
    {
        $permissions = [
            self::ROLE_SUPER_ADMIN => self::PERMISSIONS,
            self::ROLE_ADMIN => [
                'users.view', 'users.create', 'users.edit', 'users.delete',
                'streams.view', 'streams.create', 'streams.edit', 'streams.delete',
                'categories.view', 'categories.create', 'categories.edit', 'categories.delete',
                'settings.view', 'settings.edit',
                'logs.view', 'reports.view'
            ],
            self::ROLE_MODERATOR => [
                'users.view', 'users.edit',
                'streams.view', 'streams.edit',
                'categories.view',
                'logs.view', 'reports.view'
            ],
            self::ROLE_SUPPORT => [
                'users.view',
                'streams.view',
                'categories.view',
                'logs.view'
            ]
        ];
        
        return $permissions[$role] ?? [];
    }

    /**
     * SECURITY: Scope to get active admins only
     */
    public function scopeActive($query)
    {
        return $query->where('active', true);
    }

    /**
     * SECURITY: Scope to get non-locked admins
     */
    public function scopeNotLocked($query)
    {
        return $query->where(function ($q) {
            $q->whereNull('locked_until')
              ->orWhere('locked_until', '<=', now());
        });
    }

    /**
     * SECURITY: Create admin with validation and sanitization
     */
    public static function createSecure(array $data): ?self
    {
        try {
            // Validate required fields
            if (empty($data['username']) || empty($data['email']) || empty($data['password'])) {
                throw new InvalidArgumentException('Missing required fields');
            }
            
            // Check for duplicate username/email
            if (static::where('username', $data['username'])->exists()) {
                throw new InvalidArgumentException('Username already exists');
            }
            
            if (static::where('email', $data['email'])->exists()) {
                throw new InvalidArgumentException('Email already exists');
            }
            
            $admin = new static();
            $admin->fill($data);
            
            // Set default permissions based on role
            if (empty($admin->permissions)) {
                $admin->permissions = static::getDefaultPermissionsForRole($admin->role);
            }
            
            $admin->save();
            
            error_log("SECURITY: New admin created - ID: {$admin->id}, Username: {$admin->username}, Role: {$admin->role}");
            
            return $admin;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to create admin: " . $e->getMessage());
            return null;
        }
    }

    /**
     * SECURITY: Log admin actions for audit trail
     */
    protected static function boot(): void
    {
        parent::boot();
        
        static::created(function ($admin) {
            error_log("AUDIT: Admin created - ID: {$admin->id}, Username: {$admin->username}");
        });
        
        static::updated(function ($admin) {
            $changes = $admin->getDirty();
            unset($changes['password'], $changes['remember_token']); // Don't log sensitive fields
            
            if (!empty($changes)) {
                error_log("AUDIT: Admin updated - ID: {$admin->id}, Username: {$admin->username}, Changes: " . json_encode(array_keys($changes)));
            }
        });
        
        static::deleted(function ($admin) {
            error_log("AUDIT: Admin deleted - ID: {$admin->id}, Username: {$admin->username}");
        });
    }

    /**
     * SECURITY: Clean old login attempts and locks
     */
    public static function cleanOldSecurityData(): int
    {
        try {
            // Unlock accounts that should be unlocked
            $unlocked = static::where('locked_until', '<=', now())
                             ->whereNotNull('locked_until')
                             ->update([
                                 'locked_until' => null,
                                 'failed_login_attempts' => 0
                             ]);
            
            error_log("SECURITY: Cleaned {$unlocked} old admin security records");
            return $unlocked;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to clean old admin security data: " . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get the admin's full name
     */
    public function getFullNameAttribute(): string
    {
        return trim("{$this->first_name} {$this->last_name}");
    }

    /**
     * Check if admin needs to verify email
     */
    public function needsEmailVerification(): bool
    {
        return !$this->email_verified_at;
    }

    /**
     * Mark email as verified
     */
    public function markEmailAsVerified(): void
    {
        $this->email_verified_at = now();
        $this->save();
    }
}
?>

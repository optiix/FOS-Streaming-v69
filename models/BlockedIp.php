<?php
declare(strict_types=1);

/**
 * BlockedIp Model
 * FOS-Streaming Secure IP Blocking System
 * PHP 8.1+ compatible with comprehensive security enhancements
 */

class BlockedIp extends FosStreaming 
{
    /**
     * The table associated with the model
     */
    protected $table = 'blocked_ips';

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
        'ip_address',
        'ip_range_start',
        'ip_range_end',
        'reason',
        'blocked_by',
        'expires_at',
        'is_permanent',
        'block_type',
        'attempts_count',
        'last_attempt_at',
        'country_code',
        'user_agent',
        'notes'
    ];

    /**
     * The attributes that should be hidden for serialization
     */
    protected $hidden = [
        'user_agent'
    ];

    /**
     * The attributes that should be cast to native types
     */
    protected $casts = [
        'blocked_by' => 'integer',
        'expires_at' => 'datetime',
        'is_permanent' => 'boolean',
        'attempts_count' => 'integer',
        'last_attempt_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime'
    ];

    /**
     * Block types
     */
    public const TYPE_MANUAL = 'manual';
    public const TYPE_AUTOMATIC = 'automatic';
    public const TYPE_FAILED_LOGIN = 'failed_login';
    public const TYPE_RATE_LIMIT = 'rate_limit';
    public const TYPE_SUSPICIOUS = 'suspicious';
    public const TYPE_SPAM = 'spam';
    public const TYPE_MALWARE = 'malware';
    public const TYPE_COUNTRY = 'country';

    /**
     * Block reasons
     */
    public const REASON_FAILED_LOGINS = 'Too many failed login attempts';
    public const REASON_RATE_LIMIT = 'Rate limit exceeded';
    public const REASON_SUSPICIOUS_ACTIVITY = 'Suspicious activity detected';
    public const REASON_MANUAL_BLOCK = 'Manually blocked by administrator';
    public const REASON_SPAM = 'Spam or abuse detected';
    public const REASON_MALWARE = 'Malware or security threat';
    public const REASON_COUNTRY_BLOCK = 'Country-based blocking';

    /**
     * Validation rules for blocked IP data
     */
    public static function validationRules(): array
    {
        return [
            'ip_address' => 'nullable|ip',
            'ip_range_start' => 'nullable|ip',
            'ip_range_end' => 'nullable|ip',
            'reason' => 'required|string|max:500',
            'blocked_by' => 'nullable|integer|min:1',
            'expires_at' => 'nullable|date|after:now',
            'is_permanent' => 'boolean',
            'block_type' => 'required|string|in:' . implode(',', [
                self::TYPE_MANUAL,
                self::TYPE_AUTOMATIC,
                self::TYPE_FAILED_LOGIN,
                self::TYPE_RATE_LIMIT,
                self::TYPE_SUSPICIOUS,
                self::TYPE_SPAM,
                self::TYPE_MALWARE,
                self::TYPE_COUNTRY
            ]),
            'attempts_count' => 'nullable|integer|min:0',
            'country_code' => 'nullable|string|size:2',
            'notes' => 'nullable|string|max:1000'
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
                case 'ip_address':
                case 'ip_range_start':
                case 'ip_range_end':
                    $sanitized[$key] = filter_var($value, FILTER_VALIDATE_IP) ?: null;
                    break;
                    
                case 'reason':
                case 'notes':
                    $sanitized[$key] = htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8');
                    break;
                    
                case 'blocked_by':
                case 'attempts_count':
                    $sanitized[$key] = is_numeric($value) ? (int)$value : null;
                    break;
                    
                case 'block_type':
                    $validTypes = [
                        self::TYPE_MANUAL,
                        self::TYPE_AUTOMATIC,
                        self::TYPE_FAILED_LOGIN,
                        self::TYPE_RATE_LIMIT,
                        self::TYPE_SUSPICIOUS,
                        self::TYPE_SPAM,
                        self::TYPE_MALWARE,
                        self::TYPE_COUNTRY
                    ];
                    $sanitized[$key] = in_array($value, $validTypes) ? $value : self::TYPE_AUTOMATIC;
                    break;
                    
                case 'country_code':
                    $sanitized[$key] = strtoupper(preg_replace('/[^A-Z]/', '', $value));
                    if (strlen($sanitized[$key]) !== 2) {
                        $sanitized[$key] = null;
                    }
                    break;
                    
                case 'is_permanent':
                    $sanitized[$key] = (bool)$value;
                    break;
                    
                case 'user_agent':
                    $sanitized[$key] = substr(htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8'), 0, 500);
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
     * Relationship: Get the admin who blocked this IP
     */
    public function blockedByAdmin()
    {
        return $this->belongsTo(Admin::class, 'blocked_by', 'id');
    }

    /**
     * SECURITY: Check if an IP address is blocked
     */
    public static function isBlocked(string $ipAddress): bool
    {
        // Validate IP first
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        try {
            // Check for exact IP match
            $exactMatch = static::where('ip_address', $ipAddress)
                               ->where(function ($query) {
                                   $query->where('is_permanent', true)
                                         ->orWhere('expires_at', '>', now())
                                         ->orWhereNull('expires_at');
                               })
                               ->exists();
            
            if ($exactMatch) {
                return true;
            }
            
            // Check for IP range blocks
            $ipLong = ip2long($ipAddress);
            if ($ipLong !== false) {
                $rangeMatch = static::whereNotNull('ip_range_start')
                                   ->whereNotNull('ip_range_end')
                                   ->where(function ($query) {
                                       $query->where('is_permanent', true)
                                             ->orWhere('expires_at', '>', now())
                                             ->orWhereNull('expires_at');
                                   })
                                   ->get()
                                   ->filter(function ($block) use ($ipLong) {
                                       $startLong = ip2long($block->ip_range_start);
                                       $endLong = ip2long($block->ip_range_end);
                                       return $startLong !== false && $endLong !== false && 
                                              $ipLong >= $startLong && $ipLong <= $endLong;
                                   })
                                   ->isNotEmpty();
                
                if ($rangeMatch) {
                    return true;
                }
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log("SECURITY: Error checking blocked IP {$ipAddress}: " . $e->getMessage());
            return false;
        }
    }

    /**
     * SECURITY: Get block information for an IP
     */
    public static function getBlockInfo(string $ipAddress): ?array
    {
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            return null;
        }
        
        try {
            // Check exact match first
            $block = static::where('ip_address', $ipAddress)
                          ->where(function ($query) {
                              $query->where('is_permanent', true)
                                    ->orWhere('expires_at', '>', now())
                                    ->orWhereNull('expires_at');
                          })
                          ->first();
            
            if ($block) {
                return [
                    'blocked' => true,
                    'reason' => $block->reason,
                    'type' => $block->block_type,
                    'expires_at' => $block->expires_at,
                    'is_permanent' => $block->is_permanent,
                    'blocked_at' => $block->created_at
                ];
            }
            
            // Check range blocks
            $ipLong = ip2long($ipAddress);
            if ($ipLong !== false) {
                $rangeBlock = static::whereNotNull('ip_range_start')
                                   ->whereNotNull('ip_range_end')
                                   ->where(function ($query) {
                                       $query->where('is_permanent', true)
                                             ->orWhere('expires_at', '>', now())
                                             ->orWhereNull('expires_at');
                                   })
                                   ->get()
                                   ->first(function ($block) use ($ipLong) {
                                       $startLong = ip2long($block->ip_range_start);
                                       $endLong = ip2long($block->ip_range_end);
                                       return $startLong !== false && $endLong !== false && 
                                              $ipLong >= $startLong && $ipLong <= $endLong;
                                   });
                
                if ($rangeBlock) {
                    return [
                        'blocked' => true,
                        'reason' => $rangeBlock->reason,
                        'type' => $rangeBlock->block_type,
                        'expires_at' => $rangeBlock->expires_at,
                        'is_permanent' => $rangeBlock->is_permanent,
                        'blocked_at' => $rangeBlock->created_at,
                        'range' => $rangeBlock->ip_range_start . ' - ' . $rangeBlock->ip_range_end
                    ];
                }
            }
            
            return ['blocked' => false];
            
        } catch (Exception $e) {
            error_log("SECURITY: Error getting block info for {$ipAddress}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * SECURITY: Block an IP address
     */
    public static function blockIp(string $ipAddress, array $options = []): ?self
    {
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException('Invalid IP address');
        }
        
        // Check if already blocked
        if (static::isBlocked($ipAddress)) {
            return static::where('ip_address', $ipAddress)->first();
        }
        
        try {
            $blockData = [
                'ip_address' => $ipAddress,
                'reason' => $options['reason'] ?? self::REASON_MANUAL_BLOCK,
                'block_type' => $options['type'] ?? self::TYPE_MANUAL,
                'blocked_by' => $options['blocked_by'] ?? null,
                'is_permanent' => $options['is_permanent'] ?? false,
                'expires_at' => $options['expires_at'] ?? null,
                'attempts_count' => $options['attempts_count'] ?? 0,
                'last_attempt_at' => $options['last_attempt_at'] ?? now(),
                'country_code' => $options['country_code'] ?? null,
                'user_agent' => $options['user_agent'] ?? null,
                'notes' => $options['notes'] ?? null
            ];
            
            $blocked = static::create($blockData);
            
            error_log("SECURITY: IP blocked - {$ipAddress}, Reason: {$blockData['reason']}, Type: {$blockData['block_type']}");
            
            return $blocked;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to block IP {$ipAddress}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * SECURITY: Block IP range
     */
    public static function blockIpRange(string $startIp, string $endIp, array $options = []): ?self
    {
        if (!filter_var($startIp, FILTER_VALIDATE_IP) || !filter_var($endIp, FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException('Invalid IP address range');
        }
        
        // Validate range
        $startLong = ip2long($startIp);
        $endLong = ip2long($endIp);
        
        if ($startLong === false || $endLong === false || $startLong > $endLong) {
            throw new InvalidArgumentException('Invalid IP range');
        }
        
        try {
            $blockData = [
                'ip_range_start' => $startIp,
                'ip_range_end' => $endIp,
                'reason' => $options['reason'] ?? self::REASON_MANUAL_BLOCK,
                'block_type' => $options['type'] ?? self::TYPE_MANUAL,
                'blocked_by' => $options['blocked_by'] ?? null,
                'is_permanent' => $options['is_permanent'] ?? false,
                'expires_at' => $options['expires_at'] ?? null,
                'notes' => $options['notes'] ?? null
            ];
            
            $blocked = static::create($blockData);
            
            error_log("SECURITY: IP range blocked - {$startIp} to {$endIp}, Reason: {$blockData['reason']}");
            
            return $blocked;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to block IP range {$startIp}-{$endIp}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * SECURITY: Unblock an IP address
     */
    public static function unblockIp(string $ipAddress): bool
    {
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        try {
            $deleted = static::where('ip_address', $ipAddress)->delete();
            
            if ($deleted > 0) {
                error_log("SECURITY: IP unblocked - {$ipAddress}");
                return true;
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to unblock IP {$ipAddress}: " . $e->getMessage());
            return false;
        }
    }

    /**
     * SECURITY: Auto-block IP after failed attempts
     */
    public static function autoBlockForFailedAttempts(string $ipAddress, int $attempts = 5, int $blockMinutes = 60): ?self
    {
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            return null;
        }
        
        return static::blockIp($ipAddress, [
            'reason' => self::REASON_FAILED_LOGINS,
            'type' => self::TYPE_FAILED_LOGIN,
            'attempts_count' => $attempts,
            'expires_at' => now()->addMinutes($blockMinutes),
            'last_attempt_at' => now()
        ]);
    }

    /**
     * SECURITY: Auto-block for rate limiting
     */
    public static function autoBlockForRateLimit(string $ipAddress, int $blockMinutes = 30): ?self
    {
        if (!filter_var($ipAddress, FILTER_VALIDATE_IP)) {
            return null;
        }
        
        return static::blockIp($ipAddress, [
            'reason' => self::REASON_RATE_LIMIT,
            'type' => self::TYPE_RATE_LIMIT,
            'expires_at' => now()->addMinutes($blockMinutes),
            'last_attempt_at' => now()
        ]);
    }

    /**
     * SECURITY: Clean expired blocks
     */
    public static function cleanExpiredBlocks(): int
    {
        try {
            $deleted = static::where('is_permanent', false)
                            ->where('expires_at', '<=', now())
                            ->delete();
            
            if ($deleted > 0) {
                error_log("SECURITY: Cleaned {$deleted} expired IP blocks");
            }
            
            return $deleted;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to clean expired blocks: " . $e->getMessage());
            return 0;
        }
    }

    /**
     * SECURITY: Get blocked IPs with pagination
     */
    public static function getBlockedList(int $page = 1, int $perPage = 50): array
    {
        try {
            $query = static::with('blockedByAdmin')
                          ->orderBy('created_at', 'desc');
            
            $total = $query->count();
            $blocks = $query->skip(($page - 1) * $perPage)
                           ->take($perPage)
                           ->get();
            
            return [
                'data' => $blocks,
                'total' => $total,
                'page' => $page,
                'per_page' => $perPage,
                'last_page' => ceil($total / $perPage)
            ];
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to get blocked list: " . $e->getMessage());
            return ['data' => [], 'total' => 0, 'page' => 1, 'per_page' => $perPage, 'last_page' => 1];
        }
    }

    /**
     * SECURITY: Scope for active blocks
     */
    public function scopeActive($query)
    {
        return $query->where(function ($q) {
            $q->where('is_permanent', true)
              ->orWhere('expires_at', '>', now())
              ->orWhereNull('expires_at');
        });
    }

    /**
     * SECURITY: Scope for expired blocks
     */
    public function scopeExpired($query)
    {
        return $query->where('is_permanent', false)
                    ->where('expires_at', '<=', now());
    }

    /**
     * Check if block is currently active
     */
    public function isActive(): bool
    {
        if ($this->is_permanent) {
            return true;
        }
        
        if (!$this->expires_at) {
            return true;
        }
        
        return $this->expires_at->isFuture();
    }

    /**
     * Get human-readable time until expiry
     */
    public function getTimeUntilExpiryAttribute(): ?string
    {
        if ($this->is_permanent) {
            return 'Permanent';
        }
        
        if (!$this->expires_at) {
            return 'No expiry';
        }
        
        if ($this->expires_at->isPast()) {
            return 'Expired';
        }
        
        return $this->expires_at->diffForHumans();
    }

    /**
     * Boot method for model events
     */
    protected static function boot(): void
    {
        parent::boot();
        
        static::created(function ($block) {
            error_log("AUDIT: IP block created - IP: {$block->ip_address}, Range: {$block->ip_range_start}-{$block->ip_range_end}, Type: {$block->block_type}");
        });
        
        static::deleted(function ($block) {
            error_log("AUDIT: IP block removed - IP: {$block->ip_address}, Range: {$block->ip_range_start}-{$block->ip_range_end}");
        });
    }
}
?>

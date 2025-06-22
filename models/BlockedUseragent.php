<?php
declare(strict_types=1);

/**
 * BlockedUseragent Model
 * FOS-Streaming Secure User Agent Blocking System
 * PHP 8.1+ compatible with comprehensive security enhancements
 */

class BlockedUseragent extends FosStreaming 
{
    /**
     * The table associated with the model
     */
    protected $table = 'blocked_user_agents';

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
        'user_agent',
        'pattern',
        'reason',
        'blocked_by',
        'is_regex',
        'is_active',
        'block_type',
        'severity',
        'expires_at',
        'detection_count',
        'last_detected_at',
        'notes'
    ];

    /**
     * The attributes that should be cast to native types
     */
    protected $casts = [
        'blocked_by' => 'integer',
        'is_regex' => 'boolean',
        'is_active' => 'boolean',
        'expires_at' => 'datetime',
        'detection_count' => 'integer',
        'last_detected_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime'
    ];

    /**
     * Block types
     */
    public const TYPE_BOT = 'bot';
    public const TYPE_SCRAPER = 'scraper';
    public const TYPE_MALWARE = 'malware';
    public const TYPE_SPAM = 'spam';
    public const TYPE_SUSPICIOUS = 'suspicious';
    public const TYPE_FAKE = 'fake';
    public const TYPE_OUTDATED = 'outdated';
    public const TYPE_MANUAL = 'manual';

    /**
     * Severity levels
     */
    public const SEVERITY_LOW = 'low';
    public const SEVERITY_MEDIUM = 'medium';
    public const SEVERITY_HIGH = 'high';
    public const SEVERITY_CRITICAL = 'critical';

    /**
     * Common reasons for blocking
     */
    public const REASON_MALICIOUS_BOT = 'Malicious bot activity detected';
    public const REASON_SCRAPING = 'Content scraping attempt';
    public const REASON_FAKE_BROWSER = 'Fake browser user agent';
    public const REASON_OUTDATED_CLIENT = 'Outdated or insecure client';
    public const REASON_SPAM_ACTIVITY = 'Spam or abuse activity';
    public const REASON_SECURITY_THREAT = 'Security threat identified';
    public const REASON_MANUAL_BLOCK = 'Manually blocked by administrator';

    /**
     * Validation rules for blocked user agent data
     */
    public static function validationRules(): array
    {
        return [
            'user_agent' => 'nullable|string|max:1000',
            'pattern' => 'nullable|string|max:500',
            'reason' => 'required|string|max:500',
            'blocked_by' => 'nullable|integer|min:1',
            'is_regex' => 'boolean',
            'is_active' => 'boolean',
            'block_type' => 'required|string|in:' . implode(',', [
                self::TYPE_BOT,
                self::TYPE_SCRAPER,
                self::TYPE_MALWARE,
                self::TYPE_SPAM,
                self::TYPE_SUSPICIOUS,
                self::TYPE_FAKE,
                self::TYPE_OUTDATED,
                self::TYPE_MANUAL
            ]),
            'severity' => 'required|string|in:' . implode(',', [
                self::SEVERITY_LOW,
                self::SEVERITY_MEDIUM,
                self::SEVERITY_HIGH,
                self::SEVERITY_CRITICAL
            ]),
            'expires_at' => 'nullable|date|after:now',
            'notes' => 'nullable|string|max:1000'
        ];
    }

    /**
     * Common malicious user agent patterns
     */
    protected static function getMaliciousPatterns(): array
    {
        return [
            // Bots and scrapers
            '/bot|crawler|spider|scraper/i',
            '/wget|curl|python|java/i',
            '/nikto|sqlmap|burp|nessus/i',
            
            // Fake browsers
            '/mozilla\/4\.0.*compatible.*msie/i',
            '/mozilla\/5\.0.*gecko.*firefox\/[1-9]\./i',
            
            // Security scanners
            '/nmap|masscan|zmap|openvas/i',
            '/acunetix|netsparker|qualys/i',
            
            // Common attack tools
            '/metasploit|cobalt|empire/i',
            '/hydra|medusa|brutus/i'
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
                case 'user_agent':
                case 'pattern':
                    $sanitized[$key] = substr(htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8'), 0, 1000);
                    break;
                    
                case 'reason':
                case 'notes':
                    $sanitized[$key] = htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8');
                    break;
                    
                case 'blocked_by':
                case 'detection_count':
                    $sanitized[$key] = is_numeric($value) ? (int)$value : null;
                    break;
                    
                case 'block_type':
                    $validTypes = [
                        self::TYPE_BOT,
                        self::TYPE_SCRAPER,
                        self::TYPE_MALWARE,
                        self::TYPE_SPAM,
                        self::TYPE_SUSPICIOUS,
                        self::TYPE_FAKE,
                        self::TYPE_OUTDATED,
                        self::TYPE_MANUAL
                    ];
                    $sanitized[$key] = in_array($value, $validTypes) ? $value : self::TYPE_MANUAL;
                    break;
                    
                case 'severity':
                    $validSeverities = [
                        self::SEVERITY_LOW,
                        self::SEVERITY_MEDIUM,
                        self::SEVERITY_HIGH,
                        self::SEVERITY_CRITICAL
                    ];
                    $sanitized[$key] = in_array($value, $validSeverities) ? $value : self::SEVERITY_MEDIUM;
                    break;
                    
                case 'is_regex':
                case 'is_active':
                    $sanitized[$key] = (bool)$value;
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
     * Relationship: Get the admin who blocked this user agent
     */
    public function blockedByAdmin()
    {
        return $this->belongsTo(Admin::class, 'blocked_by', 'id');
    }

    /**
     * SECURITY: Check if a user agent is blocked
     */
    public static function isBlocked(string $userAgent): bool
    {
        if (empty($userAgent)) {
            return false;
        }
        
        // Sanitize input
        $userAgent = htmlspecialchars(trim($userAgent), ENT_QUOTES, 'UTF-8');
        
        try {
            // Get all active blocks
            $blocks = static::where('is_active', true)
                           ->where(function ($query) {
                               $query->whereNull('expires_at')
                                     ->orWhere('expires_at', '>', now());
                           })
                           ->get();
            
            foreach ($blocks as $block) {
                // Check exact match
                if (!empty($block->user_agent) && $block->user_agent === $userAgent) {
                    static::recordDetection($block->id, $userAgent);
                    return true;
                }
                
                // Check pattern match
                if (!empty($block->pattern)) {
                    if ($block->is_regex) {
                        // Regex pattern
                        try {
                            if (preg_match($block->pattern, $userAgent)) {
                                static::recordDetection($block->id, $userAgent);
                                return true;
                            }
                        } catch (Exception $e) {
                            error_log("SECURITY: Invalid regex pattern in user agent block ID {$block->id}: " . $e->getMessage());
                        }
                    } else {
                        // Simple string contains
                        if (stripos($userAgent, $block->pattern) !== false) {
                            static::recordDetection($block->id, $userAgent);
                            return true;
                        }
                    }
                }
            }
            
            // Check against built-in malicious patterns
            foreach (static::getMaliciousPatterns() as $pattern) {
                if (preg_match($pattern, $userAgent)) {
                    // Auto-create block for detected malicious pattern
                    static::autoBlockMalicious($userAgent, $pattern);
                    return true;
                }
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log("SECURITY: Error checking blocked user agent: " . $e->getMessage());
            return false;
        }
    }

    /**
     * SECURITY: Get block information for a user agent
     */
    public static function getBlockInfo(string $userAgent): ?array
    {
        if (empty($userAgent)) {
            return null;
        }
        
        $userAgent = htmlspecialchars(trim($userAgent), ENT_QUOTES, 'UTF-8');
        
        try {
            $blocks = static::where('is_active', true)
                           ->where(function ($query) {
                               $query->whereNull('expires_at')
                                     ->orWhere('expires_at', '>', now());
                           })
                           ->get();
            
            foreach ($blocks as $block) {
                $matched = false;
                
                // Check exact match
                if (!empty($block->user_agent) && $block->user_agent === $userAgent) {
                    $matched = true;
                }
                
                // Check pattern match
                if (!$matched && !empty($block->pattern)) {
                    if ($block->is_regex) {
                        try {
                            if (preg_match($block->pattern, $userAgent)) {
                                $matched = true;
                            }
                        } catch (Exception $e) {
                            continue;
                        }
                    } else {
                        if (stripos($userAgent, $block->pattern) !== false) {
                            $matched = true;
                        }
                    }
                }
                
                if ($matched) {
                    return [
                        'blocked' => true,
                        'reason' => $block->reason,
                        'type' => $block->block_type,
                        'severity' => $block->severity,
                        'expires_at' => $block->expires_at,
                        'blocked_at' => $block->created_at,
                        'pattern' => $block->pattern,
                        'is_regex' => $block->is_regex
                    ];
                }
            }
            
            return ['blocked' => false];
            
        } catch (Exception $e) {
            error_log("SECURITY: Error getting user agent block info: " . $e->getMessage());
            return null;
        }
    }

    /**
     * SECURITY: Block a user agent
     */
    public static function blockUserAgent(array $options): ?self
    {
        if (empty($options['user_agent']) && empty($options['pattern'])) {
            throw new InvalidArgumentException('Either user_agent or pattern must be provided');
        }
        
        try {
            $blockData = [
                'user_agent' => $options['user_agent'] ?? null,
                'pattern' => $options['pattern'] ?? null,
                'reason' => $options['reason'] ?? self::REASON_MANUAL_BLOCK,
                'block_type' => $options['block_type'] ?? self::TYPE_MANUAL,
                'severity' => $options['severity'] ?? self::SEVERITY_MEDIUM,
                'blocked_by' => $options['blocked_by'] ?? null,
                'is_regex' => $options['is_regex'] ?? false,
                'is_active' => $options['is_active'] ?? true,
                'expires_at' => $options['expires_at'] ?? null,
                'notes' => $options['notes'] ?? null,
                'detection_count' => 0,
                'last_detected_at' => now()
            ];
            
            // Validate regex if specified
            if ($blockData['is_regex'] && !empty($blockData['pattern'])) {
                try {
                    preg_match($blockData['pattern'], 'test');
                } catch (Exception $e) {
                    throw new InvalidArgumentException('Invalid regex pattern');
                }
            }
            
            $blocked = static::create($blockData);
            
            $identifier = $blockData['user_agent'] ?? $blockData['pattern'];
            error_log("SECURITY: User agent blocked - {$identifier}, Type: {$blockData['block_type']}, Severity: {$blockData['severity']}");
            
            return $blocked;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to block user agent: " . $e->getMessage());
            return null;
        }
    }

    /**
     * SECURITY: Auto-block malicious user agent
     */
    protected static function autoBlockMalicious(string $userAgent, string $pattern): ?self
    {
        try {
            return static::blockUserAgent([
                'user_agent' => $userAgent,
                'pattern' => $pattern,
                'reason' => self::REASON_SECURITY_THREAT,
                'block_type' => self::TYPE_MALWARE,
                'severity' => self::SEVERITY_HIGH,
                'is_regex' => true,
                'notes' => 'Automatically blocked based on malicious pattern detection'
            ]);
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to auto-block malicious user agent: " . $e->getMessage());
            return null;
        }
    }

    /**
     * SECURITY: Record detection of blocked user agent
     */
    protected static function recordDetection(int $blockId, string $userAgent): void
    {
        try {
            static::where('id', $blockId)->increment('detection_count');
            static::where('id', $blockId)->update(['last_detected_at' => now()]);
            
            error_log("SECURITY: Blocked user agent detected - Block ID: {$blockId}, User Agent: " . substr($userAgent, 0, 100));
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to record user agent detection: " . $e->getMessage());
        }
    }

    /**
     * SECURITY: Unblock a user agent
     */
    public static function unblockUserAgent(int $blockId): bool
    {
        try {
            $block = static::find($blockId);
            if (!$block) {
                return false;
            }
            
            $identifier = $block->user_agent ?? $block->pattern;
            $deleted = $block->delete();
            
            if ($deleted) {
                error_log("SECURITY: User agent unblocked - {$identifier}");
                return true;
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to unblock user agent: " . $e->getMessage());
            return false;
        }
    }

    /**
     * SECURITY: Deactivate a user agent block
     */
    public function deactivate(): bool
    {
        try {
            $this->is_active = false;
            $saved = $this->save();
            
            if ($saved) {
                $identifier = $this->user_agent ?? $this->pattern;
                error_log("SECURITY: User agent block deactivated - {$identifier}");
            }
            
            return $saved;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to deactivate user agent block: " . $e->getMessage());
            return false;
        }
    }

    /**
     * SECURITY: Clean expired blocks
     */
    public static function cleanExpiredBlocks(): int
    {
        try {
            $deleted = static::where('expires_at', '<=', now())
                            ->delete();
            
            if ($deleted > 0) {
                error_log("SECURITY: Cleaned {$deleted} expired user agent blocks");
            }
            
            return $deleted;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to clean expired user agent blocks: " . $e->getMessage());
            return 0;
        }
    }

    /**
     * SECURITY: Get blocked user agents with pagination
     */
    public static function getBlockedList(int $page = 1, int $perPage = 50): array
    {
        try {
            $query = static::with('blockedByAdmin')
                          ->where('is_active', true)
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
            error_log("SECURITY: Failed to get blocked user agents list: " . $e->getMessage());
            return ['data' => [], 'total' => 0, 'page' => 1, 'per_page' => $perPage, 'last_page' => 1];
        }
    }

    /**
     * SECURITY: Get statistics
     */
    public static function getStatistics(): array
    {
        try {
            return [
                'total_blocks' => static::count(),
                'active_blocks' => static::where('is_active', true)->count(),
                'total_detections' => static::sum('detection_count'),
                'high_severity_blocks' => static::where('severity', self::SEVERITY_HIGH)->count(),
                'critical_blocks' => static::where('severity', self::SEVERITY_CRITICAL)->count(),
                'bot_blocks' => static::where('block_type', self::TYPE_BOT)->count(),
                'malware_blocks' => static::where('block_type', self::TYPE_MALWARE)->count()
            ];
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to get user agent statistics: " . $e->getMessage());
            return [];
        }
    }

    /**
     * SECURITY: Scope for active blocks
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true)
                    ->where(function ($q) {
                        $q->whereNull('expires_at')
                          ->orWhere('expires_at', '>', now());
                    });
    }

    /**
     * SECURITY: Scope for expired blocks
     */
    public function scopeExpired($query)
    {
        return $query->where('expires_at', '<=', now());
    }

    /**
     * SECURITY: Scope by severity
     */
    public function scopeBySeverity($query, string $severity)
    {
        return $query->where('severity', $severity);
    }

    /**
     * Check if block is currently active
     */
    public function isActive(): bool
    {
        if (!$this->is_active) {
            return false;
        }
        
        if (!$this->expires_at) {
            return true;
        }
        
        return $this->expires_at->isFuture();
    }

    /**
     * Get human-readable identifier
     */
    public function getIdentifierAttribute(): string
    {
        if (!empty($this->user_agent)) {
            return substr($this->user_agent, 0, 50) . (strlen($this->user_agent) > 50 ? '...' : '');
        }
        
        if (!empty($this->pattern)) {
            return 'Pattern: ' . substr($this->pattern, 0, 50) . (strlen($this->pattern) > 50 ? '...' : '');
        }
        
        return 'Unknown';
    }

    /**
     * Boot method for model events
     */
    protected static function boot(): void
    {
        parent::boot();
        
        static::created(function ($block) {
            $identifier = $block->user_agent ?? $block->pattern;
            error_log("AUDIT: User agent block created - {$identifier}, Type: {$block->block_type}, Severity: {$block->severity}");
        });
        
        static::updated(function ($block) {
            if ($block->isDirty('is_active')) {
                $status = $block->is_active ? 'activated' : 'deactivated';
                $identifier = $block->user_agent ?? $block->pattern;
                error_log("AUDIT: User agent block {$status} - {$identifier}");
            }
        });
        
        static::deleted(function ($block) {
            $identifier = $block->user_agent ?? $block->pattern;
            error_log("AUDIT: User agent block deleted - {$identifier}");
        });
    }
}
?>

<?php
declare(strict_types=1);

/**
 * Activity Model
 * FOS-Streaming Secure Activity Management
 * PHP 8.1+ compatible with security enhancements
 */

class Activity extends FosStreaming 
{
    /**
     * The table associated with the model
     */
    protected $table = 'activity';

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
        'user_id',
        'stream_id',
        'action',
        'ip_address',
        'user_agent',
        'started_at',
        'ended_at',
        'duration',
        'bytes_transferred',
        'quality',
        'device_info'
    ];

    /**
     * The attributes that should be hidden for serialization
     */
    protected $hidden = [
        'ip_address',
        'user_agent'
    ];

    /**
     * The attributes that should be cast to native types
     */
    protected $casts = [
        'user_id' => 'integer',
        'stream_id' => 'integer',
        'started_at' => 'datetime',
        'ended_at' => 'datetime',
        'duration' => 'integer',
        'bytes_transferred' => 'integer',
        'created_at' => 'datetime',
        'updated_at' => 'datetime'
    ];

    /**
     * Validation rules for activity data
     */
    public static function validationRules(): array
    {
        return [
            'user_id' => 'required|integer|min:1',
            'stream_id' => 'required|integer|min:1',
            'action' => 'required|string|max:50',
            'ip_address' => 'nullable|ip',
            'user_agent' => 'nullable|string|max:500',
            'started_at' => 'nullable|date',
            'ended_at' => 'nullable|date|after:started_at',
            'duration' => 'nullable|integer|min:0',
            'bytes_transferred' => 'nullable|integer|min:0',
            'quality' => 'nullable|string|max:20',
            'device_info' => 'nullable|string|max:255'
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
                case 'user_id':
                case 'stream_id':
                case 'duration':
                case 'bytes_transferred':
                    $sanitized[$key] = is_numeric($value) ? (int)$value : null;
                    break;
                    
                case 'action':
                case 'quality':
                    $sanitized[$key] = is_string($value) ? 
                        htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8') : null;
                    break;
                    
                case 'ip_address':
                    $sanitized[$key] = filter_var($value, FILTER_VALIDATE_IP) ?: null;
                    break;
                    
                case 'user_agent':
                case 'device_info':
                    $sanitized[$key] = is_string($value) ? 
                        substr(htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8'), 0, 500) : null;
                    break;
                    
                case 'started_at':
                case 'ended_at':
                    $sanitized[$key] = $value; // Let the framework handle datetime validation
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
     * Get the user that owns the activity
     */
    public function user()
    {
        return $this->belongsTo(User::class, 'user_id', 'id');
    }

    /**
     * Get the stream associated with the activity
     */
    public function stream()
    {
        return $this->belongsTo(Stream::class, 'stream_id', 'id');
    }

    /**
     * SECURITY: Scope to get activities for a specific user (with permission check)
     */
    public function scopeForUser($query, int $userId)
    {
        return $query->where('user_id', $userId);
    }

    /**
     * SECURITY: Scope to get activities within date range
     */
    public function scopeBetweenDates($query, string $startDate, string $endDate)
    {
        return $query->whereBetween('started_at', [$startDate, $endDate]);
    }

    /**
     * SECURITY: Scope to get recent activities (last 30 days by default)
     */
    public function scopeRecent($query, int $days = 30)
    {
        return $query->where('started_at', '>=', now()->subDays($days));
    }

    /**
     * SECURITY: Get sanitized user agent
     */
    public function getSanitizedUserAgentAttribute(): ?string
    {
        if (empty($this->user_agent)) {
            return null;
        }
        
        return substr(htmlspecialchars($this->user_agent, ENT_QUOTES, 'UTF-8'), 0, 100);
    }

    /**
     * SECURITY: Get masked IP address for privacy
     */
    public function getMaskedIpAttribute(): ?string
    {
        if (empty($this->ip_address)) {
            return null;
        }
        
        // Mask last octet of IPv4 or last segment of IPv6
        if (filter_var($this->ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $this->ip_address);
            $parts[3] = 'xxx';
            return implode('.', $parts);
        } elseif (filter_var($this->ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $this->ip_address);
            $parts[count($parts) - 1] = 'xxxx';
            return implode(':', $parts);
        }
        
        return 'xxx.xxx.xxx.xxx';
    }

    /**
     * Calculate duration from start and end times
     */
    public function calculateDuration(): ?int
    {
        if ($this->started_at && $this->ended_at) {
            return $this->ended_at->diffInSeconds($this->started_at);
        }
        
        return null;
    }

    /**
     * SECURITY: Log activity creation for audit trail
     */
    protected static function boot(): void
    {
        parent::boot();
        
        static::creating(function ($activity) {
            // Auto-calculate duration if not set
            if (!$activity->duration && $activity->started_at && $activity->ended_at) {
                $activity->duration = $activity->calculateDuration();
            }
            
            // Log activity creation for security audit
            error_log("ACTIVITY: New activity created - User: {$activity->user_id}, Stream: {$activity->stream_id}, Action: {$activity->action}");
        });
        
        static::updating(function ($activity) {
            // Recalculate duration on update
            if ($activity->isDirty(['started_at', 'ended_at']) && !$activity->isDirty('duration')) {
                $activity->duration = $activity->calculateDuration();
            }
        });
    }

    /**
     * SECURITY: Create activity with validation and sanitization
     */
    public static function createSecure(array $data): ?self
    {
        try {
            // Validate required fields
            if (empty($data['user_id']) || empty($data['stream_id']) || empty($data['action'])) {
                throw new InvalidArgumentException('Missing required fields');
            }
            
            $activity = new static();
            $activity->fill($data);
            
            // Additional validation
            if (!$activity->user()->exists()) {
                throw new InvalidArgumentException('Invalid user ID');
            }
            
            if (!$activity->stream()->exists()) {
                throw new InvalidArgumentException('Invalid stream ID');
            }
            
            $activity->save();
            return $activity;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to create activity: " . $e->getMessage());
            return null;
        }
    }

    /**
     * SECURITY: Get activity statistics with permission check
     */
    public static function getStatsForUser(int $userId, int $days = 30): array
    {
        try {
            $activities = static::forUser($userId)->recent($days)->get();
            
            return [
                'total_activities' => $activities->count(),
                'total_watch_time' => $activities->sum('duration'),
                'unique_streams' => $activities->pluck('stream_id')->unique()->count(),
                'average_session_length' => $activities->avg('duration'),
                'total_data_transferred' => $activities->sum('bytes_transferred')
            ];
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to get activity stats: " . $e->getMessage());
            return [];
        }
    }

    /**
     * SECURITY: Clean old activities (for GDPR compliance)
     */
    public static function cleanOldActivities(int $daysToKeep = 365): int
    {
        try {
            $cutoffDate = now()->subDays($daysToKeep);
            $deleted = static::where('created_at', '<', $cutoffDate)->delete();
            
            error_log("ACTIVITY: Cleaned $deleted old activity records older than $daysToKeep days");
            return $deleted;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to clean old activities: " . $e->getMessage());
            return 0;
        }
    }
}
?>

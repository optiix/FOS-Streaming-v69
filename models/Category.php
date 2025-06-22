<?php
declare(strict_types=1);

/**
 * Category Model
 * FOS-Streaming Secure Category Management
 * PHP 8.1+ compatible with comprehensive security enhancements
 */

class Category extends FosStreaming 
{
    /**
     * The table associated with the model
     */
    protected $table = 'categories';

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
        'name',
        'description',
        'slug',
        'parent_id',
        'sort_order',
        'is_active',
        'is_featured',
        'icon',
        'color',
        'access_level',
        'min_age_required',
        'country_restrictions',
        'created_by',
        'metadata'
    ];

    /**
     * The attributes that should be hidden for serialization
     */
    protected $hidden = [
        'created_by'
    ];

    /**
     * The attributes that should be cast to native types
     */
    protected $casts = [
        'parent_id' => 'integer',
        'sort_order' => 'integer',
        'is_active' => 'boolean',
        'is_featured' => 'boolean',
        'min_age_required' => 'integer',
        'country_restrictions' => 'array',
        'created_by' => 'integer',
        'metadata' => 'array',
        'created_at' => 'datetime',
        'updated_at' => 'datetime'
    ];

    /**
     * Access levels
     */
    public const ACCESS_PUBLIC = 'public';
    public const ACCESS_REGISTERED = 'registered';
    public const ACCESS_PREMIUM = 'premium';
    public const ACCESS_VIP = 'vip';
    public const ACCESS_ADMIN = 'admin';

    /**
     * Category types for better organization
     */
    public const TYPE_MOVIES = 'movies';
    public const TYPE_TV_SHOWS = 'tv_shows';
    public const TYPE_SPORTS = 'sports';
    public const TYPE_NEWS = 'news';
    public const TYPE_MUSIC = 'music';
    public const TYPE_KIDS = 'kids';
    public const TYPE_ADULT = 'adult';
    public const TYPE_DOCUMENTARY = 'documentary';
    public const TYPE_LIVE = 'live';

    /**
     * Validation rules for category data
     */
    public static function validationRules(): array
    {
        return [
            'name' => 'required|string|min:2|max:100',
            'description' => 'nullable|string|max:1000',
            'slug' => 'nullable|string|max:100|regex:/^[a-z0-9-]+$/',
            'parent_id' => 'nullable|integer|exists:categories,id',
            'sort_order' => 'nullable|integer|min:0|max:9999',
            'is_active' => 'boolean',
            'is_featured' => 'boolean',
            'icon' => 'nullable|string|max:255',
            'color' => 'nullable|string|regex:/^#[a-fA-F0-9]{6}$/',
            'access_level' => 'required|string|in:' . implode(',', [
                self::ACCESS_PUBLIC,
                self::ACCESS_REGISTERED,
                self::ACCESS_PREMIUM,
                self::ACCESS_VIP,
                self::ACCESS_ADMIN
            ]),
            'min_age_required' => 'nullable|integer|min:0|max:99',
            'country_restrictions' => 'nullable|array',
            'country_restrictions.*' => 'string|size:2',
            'created_by' => 'nullable|integer|exists:admins,id'
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
                case 'name':
                    // Allow basic characters for category names
                    $sanitized[$key] = htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8');
                    break;
                    
                case 'description':
                    // Remove potentially dangerous HTML but allow basic formatting
                    $sanitized[$key] = strip_tags(trim($value), '<b><i><em><strong><br>');
                    break;
                    
                case 'slug':
                    // Generate slug if not provided or sanitize existing
                    if (empty($value)) {
                        $sanitized[$key] = static::generateSlug($data['name'] ?? '');
                    } else {
                        $sanitized[$key] = strtolower(preg_replace('/[^a-z0-9-]/', '', $value));
                    }
                    break;
                    
                case 'parent_id':
                case 'sort_order':
                case 'min_age_required':
                case 'created_by':
                    $sanitized[$key] = is_numeric($value) ? (int)$value : null;
                    break;
                    
                case 'access_level':
                    $validLevels = [
                        self::ACCESS_PUBLIC,
                        self::ACCESS_REGISTERED,
                        self::ACCESS_PREMIUM,
                        self::ACCESS_VIP,
                        self::ACCESS_ADMIN
                    ];
                    $sanitized[$key] = in_array($value, $validLevels) ? $value : self::ACCESS_PUBLIC;
                    break;
                    
                case 'is_active':
                case 'is_featured':
                    $sanitized[$key] = (bool)$value;
                    break;
                    
                case 'icon':
                    // Validate icon path/URL
                    if (!empty($value)) {
                        $sanitized[$key] = filter_var($value, FILTER_SANITIZE_URL);
                        // Ensure it's a safe file extension
                        $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'];
                        $extension = strtolower(pathinfo($sanitized[$key], PATHINFO_EXTENSION));
                        if (!in_array($extension, $allowedExtensions)) {
                            $sanitized[$key] = null;
                        }
                    } else {
                        $sanitized[$key] = null;
                    }
                    break;
                    
                case 'color':
                    // Validate hex color
                    if (!empty($value) && preg_match('/^#[a-fA-F0-9]{6}$/', $value)) {
                        $sanitized[$key] = strtoupper($value);
                    } else {
                        $sanitized[$key] = null;
                    }
                    break;
                    
                case 'country_restrictions':
                    if (is_array($value)) {
                        $sanitized[$key] = array_map(function($country) {
                            return strtoupper(preg_replace('/[^A-Z]/', '', $country));
                        }, array_filter($value));
                        // Keep only valid 2-letter country codes
                        $sanitized[$key] = array_filter($sanitized[$key], function($code) {
                            return strlen($code) === 2;
                        });
                    } else {
                        $sanitized[$key] = [];
                    }
                    break;
                    
                case 'metadata':
                    if (is_array($value)) {
                        // Sanitize metadata recursively
                        $sanitized[$key] = static::sanitizeMetadata($value);
                    } else {
                        $sanitized[$key] = [];
                    }
                    break;
                    
                default:
                    // Skip unknown fields for security
                    continue 2;
            }
        }
        
        return $sanitized;
    }

    /**
     * SECURITY: Sanitize metadata recursively
     */
    protected static function sanitizeMetadata(array $metadata): array
    {
        $sanitized = [];
        
        foreach ($metadata as $key => $value) {
            $cleanKey = htmlspecialchars(trim($key), ENT_QUOTES, 'UTF-8');
            
            if (is_array($value)) {
                $sanitized[$cleanKey] = static::sanitizeMetadata($value);
            } elseif (is_string($value)) {
                $sanitized[$cleanKey] = htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8');
            } elseif (is_numeric($value) || is_bool($value)) {
                $sanitized[$cleanKey] = $value;
            }
        }
        
        return $sanitized;
    }

    /**
     * SECURITY: Generate URL-safe slug
     */
    public static function generateSlug(string $name): string
    {
        $slug = strtolower(trim($name));
        $slug = preg_replace('/[^a-z0-9\s-]/', '', $slug);
        $slug = preg_replace('/[\s-]+/', '-', $slug);
        $slug = trim($slug, '-');
        
        // Ensure uniqueness
        $originalSlug = $slug;
        $counter = 1;
        
        while (static::where('slug', $slug)->exists()) {
            $slug = $originalSlug . '-' . $counter;
            $counter++;
        }
        
        return $slug;
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
     * Relationship: Get streams in this category
     */
    public function streams()
    {
        return $this->hasMany(Stream::class, 'cat_id', 'id');
    }

    /**
     * Relationship: Get active streams only
     */
    public function activeStreams()
    {
        return $this->hasMany(Stream::class, 'cat_id', 'id')
                    ->where('active', 1)
                    ->where('running', 1);
    }

    /**
     * Relationship: Get parent category
     */
    public function parent()
    {
        return $this->belongsTo(static::class, 'parent_id', 'id');
    }

    /**
     * Relationship: Get child categories
     */
    public function children()
    {
        return $this->hasMany(static::class, 'parent_id', 'id');
    }

    /**
     * Relationship: Get active child categories
     */
    public function activeChildren()
    {
        return $this->hasMany(static::class, 'parent_id', 'id')
                    ->where('is_active', true)
                    ->orderBy('sort_order', 'asc');
    }

    /**
     * Relationship: Get admin who created this category
     */
    public function creator()
    {
        return $this->belongsTo(Admin::class, 'created_by', 'id');
    }

    /**
     * SECURITY: Check if user has access to this category
     */
    public function hasAccess(?User $user = null): bool
    {
        // Public categories are always accessible
        if ($this->access_level === self::ACCESS_PUBLIC) {
            return true;
        }
        
        // If no user provided and category requires registration
        if (!$user) {
            return false;
        }
        
        // Check access level
        switch ($this->access_level) {
            case self::ACCESS_REGISTERED:
                return $user->active;
                
            case self::ACCESS_PREMIUM:
                return $user->active && ($user->user_type === 'premium' || $user->user_type === 'vip');
                
            case self::ACCESS_VIP:
                return $user->active && $user->user_type === 'vip';
                
            case self::ACCESS_ADMIN:
                return $user->active && $user->is_admin;
                
            default:
                return false;
        }
    }

    /**
     * SECURITY: Check age restriction
     */
    public function meetsAgeRequirement(?int $userAge = null): bool
    {
        if (!$this->min_age_required) {
            return true;
        }
        
        if ($userAge === null) {
            return false;
        }
        
        return $userAge >= $this->min_age_required;
    }

    /**
     * SECURITY: Check country restrictions
     */
    public function isAllowedInCountry(?string $countryCode = null): bool
    {
        // No restrictions means allowed everywhere
        if (empty($this->country_restrictions)) {
            return true;
        }
        
        // If no country code provided, assume not allowed
        if (!$countryCode) {
            return false;
        }
        
        return in_array(strtoupper($countryCode), $this->country_restrictions);
    }

    /**
     * SECURITY: Scope for active categories
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    /**
     * SECURITY: Scope for featured categories
     */
    public function scopeFeatured($query)
    {
        return $query->where('is_featured', true)
                    ->where('is_active', true);
    }

    /**
     * SECURITY: Scope for top-level categories
     */
    public function scopeTopLevel($query)
    {
        return $query->whereNull('parent_id');
    }

    /**
     * SECURITY: Scope for categories accessible by user
     */
    public function scopeAccessibleBy($query, ?User $user = null)
    {
        return $query->where(function ($q) use ($user) {
            $q->where('access_level', self::ACCESS_PUBLIC);
            
            if ($user && $user->active) {
                $q->orWhere('access_level', self::ACCESS_REGISTERED);
                
                if ($user->user_type === 'premium' || $user->user_type === 'vip') {
                    $q->orWhere('access_level', self::ACCESS_PREMIUM);
                }
                
                if ($user->user_type === 'vip') {
                    $q->orWhere('access_level', self::ACCESS_VIP);
                }
                
                if ($user->is_admin) {
                    $q->orWhere('access_level', self::ACCESS_ADMIN);
                }
            }
        });
    }

    /**
     * SECURITY: Scope for categories allowed in country
     */
    public function scopeAllowedInCountry($query, ?string $countryCode = null)
    {
        if (!$countryCode) {
            return $query->whereJsonLength('country_restrictions', 0);
        }
        
        return $query->where(function ($q) use ($countryCode) {
            $q->whereJsonLength('country_restrictions', 0)
              ->orWhereJsonContains('country_restrictions', strtoupper($countryCode));
        });
    }

    /**
     * Get category hierarchy path
     */
    public function getHierarchyPath(): array
    {
        $path = [$this];
        $current = $this;
        
        while ($current->parent) {
            $path[] = $current->parent;
            $current = $current->parent;
        }
        
        return array_reverse($path);
    }

    /**
     * Get category breadcrumb
     */
    public function getBreadcrumb(): string
    {
        $path = $this->getHierarchyPath();
        return implode(' > ', array_map(function ($category) {
            return $category->name;
        }, $path));
    }

    /**
     * Get stream count
     */
    public function getStreamCountAttribute(): int
    {
        return $this->streams()->count();
    }

    /**
     * Get active stream count
     */
    public function getActiveStreamCountAttribute(): int
    {
        return $this->activeStreams()->count();
    }

    /**
     * Check if category has streams
     */
    public function hasStreams(): bool
    {
        return $this->streams()->exists();
    }

    /**
     * Check if category has active streams
     */
    public function hasActiveStreams(): bool
    {
        return $this->activeStreams()->exists();
    }

    /**
     * SECURITY: Create category with validation and sanitization
     */
    public static function createSecure(array $data): ?self
    {
        try {
            // Validate required fields
            if (empty($data['name'])) {
                throw new InvalidArgumentException('Category name is required');
            }
            
            // Check for duplicate name in same parent
            $parentId = $data['parent_id'] ?? null;
            $existing = static::where('name', $data['name'])
                             ->where('parent_id', $parentId)
                             ->exists();
            
            if ($existing) {
                throw new InvalidArgumentException('Category name already exists in this parent category');
            }
            
            $category = new static();
            $category->fill($data);
            
            // Set default sort order if not provided
            if (!isset($data['sort_order'])) {
                $maxOrder = static::where('parent_id', $parentId)->max('sort_order') ?? 0;
                $category->sort_order = $maxOrder + 1;
            }
            
            $category->save();
            
            error_log("SECURITY: Category created - ID: {$category->id}, Name: {$category->name}, Access Level: {$category->access_level}");
            
            return $category;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to create category: " . $e->getMessage());
            return null;
        }
    }

    /**
     * SECURITY: Update category with validation
     */
    public function updateSecure(array $data): bool
    {
        try {
            // Prevent circular parent relationship
            if (isset($data['parent_id']) && $data['parent_id']) {
                if ($this->isDescendantOf($data['parent_id'])) {
                    throw new InvalidArgumentException('Cannot set parent to a descendant category');
                }
            }
            
            $this->fill($data);
            $saved = $this->save();
            
            if ($saved) {
                error_log("SECURITY: Category updated - ID: {$this->id}, Name: {$this->name}");
            }
            
            return $saved;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to update category: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if category is descendant of another category
     */
    public function isDescendantOf(int $categoryId): bool
    {
        $current = $this;
        
        while ($current->parent_id) {
            if ($current->parent_id === $categoryId) {
                return true;
            }
            $current = $current->parent;
        }
        
        return false;
    }

    /**
     * SECURITY: Delete category safely
     */
    public function deleteSecure(): bool
    {
        try {
            // Check if category has streams
            if ($this->hasStreams()) {
                throw new InvalidArgumentException('Cannot delete category with streams');
            }
            
            // Move child categories to parent or root
            if ($this->children()->exists()) {
                $this->children()->update(['parent_id' => $this->parent_id]);
            }
            
            $deleted = $this->delete();
            
            if ($deleted) {
                error_log("SECURITY: Category deleted - ID: {$this->id}, Name: {$this->name}");
            }
            
            return $deleted;
            
        } catch (Exception $e) {
            error_log("SECURITY: Failed to delete category: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Boot method for model events
     */
    protected static function boot(): void
    {
        parent::boot();
        
        static::creating(function ($category) {
            // Auto-generate slug if not provided
            if (empty($category->slug)) {
                $category->slug = static::generateSlug($category->name);
            }
        });
        
        static::created(function ($category) {
            error_log("AUDIT: Category created - ID: {$category->id}, Name: {$category->name}, Slug: {$category->slug}");
        });
        
        static::updated(function ($category) {
            $changes = $category->getDirty();
            if (!empty($changes)) {
                error_log("AUDIT: Category updated - ID: {$category->id}, Changes: " . json_encode(array_keys($changes)));
            }
        });
        
        static::deleted(function ($category) {
            error_log("AUDIT: Category deleted - ID: {$category->id}, Name: {$category->name}");
        });
    }
}
?>

<?php
declare(strict_types=1);

class User extends FosStreaming {

    protected $table = 'users';

    public function categories()
    {
        return $this->belongsToMany(Category::class);
    }
    
    public function getCategoryNamesAttribute(): string
    {
        $return = "";
        $prefix = '';
        foreach($this->categories as $category)
        {
            $return .= $prefix . ' ' . $category->name . '';
            $prefix = ', ';
        }

        return $return;
    }

    public function activity()
    {
        return $this->hasMany(Activity::class);
    }

    public function laststream()
    {
        return $this->hasOne(Stream::class, 'id', 'last_stream');
    }
}

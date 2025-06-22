<?php
declare(strict_types=1);

class Category extends FosStreaming {
    public function streams()
    {
        return $this->hasMany(Stream::class, 'cat_id', 'id');
    }
}

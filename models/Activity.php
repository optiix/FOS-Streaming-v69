<?php
declare(strict_types=1);

class Activity extends FosStreaming {
    protected $table = 'activity';

    public function user()
    {
        return $this->belongsTo(User::class, 'user_id', 'id');
    }

    public function stream()
    {
        return $this->belongsTo(Stream::class, 'stream_id', 'id');
    }
}

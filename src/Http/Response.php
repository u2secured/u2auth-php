<?php

declare(strict_types=1);

namespace U2Secured\U2Auth\Http;

final class Response
{
    /** @var int */
    public $status;

    /** @var string */
    public $body;

    public function __construct(int $status, string $body)
    {
        $this->status = $status;
        $this->body = $body;
    }
}

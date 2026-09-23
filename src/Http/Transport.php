<?php

declare(strict_types=1);

namespace U2Secured\U2Auth\Http;

/**
 * The seam that makes the client testable without a network. Implementations
 * must not throw on a non-2xx status -- the client maps those to
 * U2AuthException itself, so every SDK reports the same error shape.
 *
 * @param array<int, string> $headers Raw "Name: value" lines.
 */
interface Transport
{
    public function send(string $method, string $url, array $headers, ?string $body): Response;
}

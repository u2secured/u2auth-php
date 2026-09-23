<?php

declare(strict_types=1);

namespace U2Secured\U2Auth\Http;

use U2Secured\U2Auth\U2AuthException;

final class CurlTransport implements Transport
{
    /** @var int */
    private $timeout;

    public function __construct(int $timeout = 30)
    {
        $this->timeout = $timeout;
    }

    public function send(string $method, string $url, array $headers, ?string $body): Response
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $out = curl_exec($ch);
        if ($out === false) {
            $err = curl_error($ch);
            curl_close($ch);
            // Network failure is NOT an API error: it has no status and no
            // code from us. Callers that fail closed key on this.
            throw new U2AuthException(0, 'NETWORK_ERROR', $err);
        }
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return new Response($status, (string) $out);
    }
}

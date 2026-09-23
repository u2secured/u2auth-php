<?php

declare(strict_types=1);

namespace U2Secured\U2Auth\Tests;

use U2Secured\U2Auth\Http\Response;
use U2Secured\U2Auth\Http\Transport;

/**
 * Records every request and replays queued responses. The other SDKs test
 * against a real mock HTTP server; PHP cannot run one in-process cheaply, so
 * the transport is injected instead. The assertions are the same ones: method,
 * path, headers, body.
 */
final class FakeTransport implements Transport
{
    /** @var array<int, array{method: string, url: string, headers: array, body: ?string}> */
    public $requests = [];

    /** @var array<int, Response> */
    private $queue = [];

    public function queue(int $status, string $body): void
    {
        $this->queue[] = new Response($status, $body);
    }

    public function queueJson(int $status, array $body): void
    {
        $this->queue($status, json_encode($body));
    }

    public function send(string $method, string $url, array $headers, ?string $body): Response
    {
        $this->requests[] = [
            'method' => $method,
            'url' => $url,
            'headers' => $headers,
            'body' => $body,
        ];
        if (empty($this->queue)) {
            throw new \RuntimeException('FakeTransport: no queued response for ' . $method . ' ' . $url);
        }
        return array_shift($this->queue);
    }

    public function lastRequest(): array
    {
        if (empty($this->requests)) {
            throw new \RuntimeException('FakeTransport: no requests recorded');
        }
        return $this->requests[count($this->requests) - 1];
    }
}

<?php

declare(strict_types=1);

namespace U2Secured\U2Auth\Tests;

use PHPUnit\Framework\TestCase;
use U2Secured\U2Auth\U2AuthException;
use U2Secured\U2Auth\Webhook;

final class WebhookTest extends TestCase
{
    /**
     * Huge tolerance so the vector's 2023 timestamp doesn't trip the
     * staleness check -- matches node's test (`10 ** 12`).
     */
    private const BIG_TOLERANCE = 10 ** 12;

    /** @return array<string, mixed> */
    private function vectors(): array
    {
        return json_decode(file_get_contents(__DIR__ . '/../../testvectors/webhook.json'), true);
    }

    public function testVerifiesTheSharedVector(): void
    {
        $v = $this->vectors();
        $event = Webhook::verify($v['body'], $v['signature_header'], $v['secret'], self::BIG_TOLERANCE);
        $this->assertSame($v['expected_event']['approval_id'], $event['approval_id']);
        $this->assertSame($v['expected_event']['status'], $event['status']);
        $this->assertSame($v['expected_event']['reason'], $event['reason']);
        $this->assertSame($v['expected_event']['resolved_at'], $event['resolved_at']);
    }

    public function testRejectsATamperedBody(): void
    {
        $v = $this->vectors();
        $this->expectException(U2AuthException::class);
        Webhook::verify($v['body'] . ' ', $v['signature_header'], $v['secret'], self::BIG_TOLERANCE);
    }

    public function testRejectsTheWrongSecret(): void
    {
        $v = $this->vectors();
        $this->expectException(U2AuthException::class);
        Webhook::verify($v['body'], $v['signature_header'], 'wrong', self::BIG_TOLERANCE);
    }

    /**
     * The signed timestamp is what stops a captured delivery being replayed
     * indefinitely, so an old-but-correctly-signed body must still be
     * refused. The vector's timestamp (2023) is genuinely stale against the
     * real clock under the default tolerance -- no clock injection needed.
     */
    public function testRejectsAStaleTimestamp(): void
    {
        $v = $this->vectors();
        $this->expectException(U2AuthException::class);
        Webhook::verify($v['body'], $v['signature_header'], $v['secret']);
    }

    /**
     * A validly-signed body that decodes to something other than a JSON
     * object (here, a bare JSON string) must be rejected with a single
     * catchable U2AuthException, not fall through to a PHP TypeError on the
     * declared `: array` return type. A WordPress caller who wraps the call
     * in `catch (U2AuthException $e)` per the docblock must not still get a
     * fatal.
     *
     * The vector's signature only covers the vector's body, so this
     * computes a fresh signature over a fresh (non-object) body using the
     * same secret and the current time, well inside the default tolerance.
     */
    public function testRejectsAValidlySignedNonObjectPayload(): void
    {
        $v = $this->vectors();
        $body = '"not-json"';
        $timestamp = time();
        $signature = hash_hmac('sha256', $timestamp . '.' . $body, $v['secret']);
        $header = 't=' . $timestamp . ',v1=' . $signature;

        try {
            Webhook::verify($body, $header, $v['secret']);
            $this->fail('expected U2AuthException');
        } catch (U2AuthException $e) {
            $this->assertSame('INVALID_PAYLOAD', $e->getCode());
        }
    }
}

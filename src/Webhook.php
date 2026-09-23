<?php

declare(strict_types=1);

namespace U2Secured\U2Auth;

/**
 * Verifies signed webhook deliveries. Ported from `node/src/webhook.ts` -
 * match its behaviour, not just its shape.
 */
final class Webhook
{
    /**
     * Verify the `X-U2Auth-Signature` header over the RAW request body and
     * return the decoded event.
     *
     * The body MUST be the exact bytes U2 Secured sent, not a value that has
     * been parsed and re-encoded - JSON re-serialisation (different key
     * order, whitespace, escaping) changes the bytes and the signature will
     * no longer match even though the payload is "the same" logically. In a
     * WordPress REST route this means reading the raw body yourself, e.g.
     * `$request->get_body()` (which wraps `php://input`) - never
     * `WP_REST_Request::get_json_params()`, which hands back an
     * already-decoded (and therefore already re-serialisable-different)
     * array.
     *
     * Checks the signature before the timestamp, matching node's
     * `verifyWebhook`: a forged header should never get far enough to have
     * its timestamp inspected.
     *
     * @return array<string, mixed> The decoded event.
     * @throws U2AuthException code `INVALID_SIGNATURE` for a malformed
     *                         signature header or a signature that doesn't
     *                         match; code `TIMESTAMP_OUT_OF_TOLERANCE` for a
     *                         signed timestamp outside the tolerance window;
     *                         code `INVALID_PAYLOAD` for a validly-signed
     *                         body that does not decode to a JSON object.
     */
    public static function verify(
        string $rawBody,
        string $signatureHeader,
        string $secret,
        int $toleranceSeconds = 300
    ): array {
        [$timestamp, $signature] = self::parseSignatureHeader($signatureHeader);

        $expected = hash_hmac('sha256', $timestamp . '.' . $rawBody, $secret);
        if (strlen($expected) !== strlen($signature) || !hash_equals($expected, $signature)) {
            throw new U2AuthException(0, 'INVALID_SIGNATURE', 'invalid webhook signature');
        }

        $now = time();
        if (abs($now - (int) $timestamp) > $toleranceSeconds) {
            throw new U2AuthException(0, 'TIMESTAMP_OUT_OF_TOLERANCE', 'webhook timestamp out of tolerance');
        }

        $event = json_decode($rawBody, true);
        if (!is_array($event)) {
            throw new U2AuthException(0, 'INVALID_PAYLOAD', 'webhook body is not a JSON object');
        }
        return $event;
    }

    /**
     * @return array{0: string, 1: string} [timestamp, signature] as raw strings
     */
    private static function parseSignatureHeader(string $header): array
    {
        $timestamp = null;
        $signature = null;
        foreach (explode(',', $header) as $part) {
            $kv = explode('=', trim($part), 2);
            if (count($kv) !== 2) {
                continue;
            }
            if ($kv[0] === 't') {
                $timestamp = $kv[1];
            } elseif ($kv[0] === 'v1') {
                $signature = $kv[1];
            }
        }
        if ($timestamp === null || $signature === null || !preg_match('/^-?\d+$/', $timestamp)) {
            throw new U2AuthException(0, 'INVALID_SIGNATURE', 'malformed signature header');
        }
        return [$timestamp, $signature];
    }
}

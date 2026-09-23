<?php

declare(strict_types=1);

namespace U2Secured\U2Auth;

use U2Secured\U2Auth\Http\CurlTransport;
use U2Secured\U2Auth\Http\Transport;

final class U2Auth
{
    public const DEFAULT_BASE_URL = 'https://auth.u2secured.com';

    /** @var string */
    private $apiKey;

    /** @var string */
    private $baseUrl;

    /** @var Transport */
    private $transport;

    /**
     * @param array{base_url?: string, transport?: Transport} $opts
     */
    public function __construct(string $apiKey, array $opts = [])
    {
        $this->apiKey = $apiKey;
        $this->baseUrl = rtrim($opts['base_url'] ?? self::DEFAULT_BASE_URL, '/');
        $this->transport = $opts['transport'] ?? new CurlTransport();
    }

    /**
     * Verify a TOTP code against a shared secret.
     *
     * @return array{valid: bool}
     */
    public function verifyTOTP(string $secret, string $code): array
    {
        return $this->post('/api/v1/sdk/totp/verify', [
            'secret' => $secret,
            'code' => $code,
        ]);
    }

    /**
     * Ask the user's phone to approve something.
     *
     * $opts:
     *   webhook_url     string  Override the app's configured callback.
     *   ttl             int     Seconds before the approval expires.
     *   idempotency_key string  Collapses a repeated call into the ORIGINAL
     *                           approval instead of sending a second
     *                           notification. Travels as the Idempotency-Key
     *                           header, never in the body. Derive it from
     *                           whatever identifies the attempt -- a nonce
     *                           rendered into the login form works well,
     *                           because a double-click and a back-then-resubmit
     *                           both carry the same one.
     *
     * @param array{webhook_url?: string, ttl?: int, idempotency_key?: string} $opts
     * @return array{approval_id: string, match_number: int, status: string, expires_at: string}
     */
    public function requestPush(string $userIdentifier, string $context, array $opts = []): array
    {
        $body = [
            'user_identifier' => $userIdentifier,
            'context' => $context,
        ];
        if (!empty($opts['webhook_url'])) {
            $body['webhook_url'] = $opts['webhook_url'];
        }
        if (!empty($opts['ttl'])) {
            $body['ttl'] = (int) $opts['ttl'];
        }

        $headers = [];
        if (!empty($opts['idempotency_key'])) {
            $headers['Idempotency-Key'] = $opts['idempotency_key'];
        }

        return $this->post('/api/v1/sdk/push/request', $body, $headers);
    }

    /**
     * @return array{approval_id: string, status: string, reason?: string, resolved_at?: string}
     */
    public function getPushStatus(string $approvalId): array
    {
        return $this->get('/api/v1/sdk/push/' . rawurlencode($approvalId) . '/status');
    }

    /**
     * Mint a pairing code binding $userIdentifier -- your own opaque id for the
     * user -- to whichever account redeems it in the U2 Secured app. Pass the
     * same string to requestPush afterwards; matching is case-sensitive.
     *
     * @return array{code: string, expires_at: string}
     */
    public function createPairingCode(string $userIdentifier): array
    {
        return $this->post('/api/v1/sdk/pairing-codes', ['user_identifier' => $userIdentifier]);
    }

    /**
     * Remove the link between this app and $userIdentifier.
     *
     * @throws U2AuthException ENROLMENT_NOT_FOUND if there was no such enrolment.
     */
    public function deleteEnrolment(string $userIdentifier): void
    {
        $this->delete('/api/v1/sdk/enrolments?' . http_build_query(
            ['user_identifier' => $userIdentifier],
            '',
            '&',
            PHP_QUERY_RFC3986
        ));
    }

    /**
     * List the enrolments for this app. The app is resolved from the API key --
     * there is no app_id parameter. limit <= 0 is treated as unset and omitted
     * from the query, same as an empty cursor/sort/order/user_identifier (the
     * literal string "0" is NOT treated as empty for user_identifier, since
     * it is a legitimate developer-chosen identifier).
     *
     * @param array{limit?: int, cursor?: string, sort?: string, order?: string, user_identifier?: string} $opts
     * @return array{items: array<int, array<string, mixed>>, next_cursor: string}
     */
    public function listEnrolments(array $opts = []): array
    {
        $query = [];
        if (!empty($opts['limit']) && $opts['limit'] > 0) {
            $query['limit'] = (int) $opts['limit'];
        }
        foreach (['cursor', 'sort', 'order'] as $key) {
            if (!empty($opts[$key])) {
                $query[$key] = $opts[$key];
            }
        }
        // user_identifier is an arbitrary developer-chosen string, unlike
        // cursor/sort/order (opaque token / fixed enums), so the string "0"
        // is a legitimate value here -- empty() would treat it as unset and
        // silently drop the filter, matching every item instead of just the
        // one asked for. Explicit isset()/'' check instead.
        if (isset($opts['user_identifier']) && $opts['user_identifier'] !== '') {
            $query['user_identifier'] = $opts['user_identifier'];
        }
        $qs = http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        return $this->get('/api/v1/sdk/enrolments' . ($qs !== '' ? '?' . $qs : ''));
    }

    /**
     * List the authentication events recorded for one enrolment. limit <= 0 is
     * treated as unset and omitted from the query, same as an empty cursor.
     *
     * @param array{limit?: int, cursor?: string} $opts
     * @return array{items: array<int, array<string, mixed>>, next_cursor: string}
     */
    public function listEnrolmentEvents(string $enrolmentId, array $opts = []): array
    {
        $query = [];
        if (!empty($opts['limit']) && $opts['limit'] > 0) {
            $query['limit'] = (int) $opts['limit'];
        }
        if (!empty($opts['cursor'])) {
            $query['cursor'] = $opts['cursor'];
        }
        $qs = http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        return $this->get('/api/v1/sdk/enrolments/' . rawurlencode($enrolmentId) . '/events' . ($qs !== '' ? '?' . $qs : ''));
    }

    /**
     * Look up this app's enrolment for one user identifier.
     *
     * Returns null when the user is not linked. That is deliberately NOT an
     * exception: at login, "not linked" is the normal answer, and forcing
     * callers into try/catch for the common path is how integrations end up
     * swallowing real errors too.
     *
     * @return array{id: string, user_identifier: string, created_at: string, last_auth_at: ?string, last_auth_outcome: ?string, push_ready: bool}|null
     */
    public function getEnrolment(string $userIdentifier): ?array
    {
        $page = $this->listEnrolments(['user_identifier' => $userIdentifier, 'limit' => 1]);
        if (empty($page['items'])) {
            return null;
        }
        return $page['items'][0];
    }

    /**
     * Read where a pairing code is in its lifecycle: pending, redeemed or
     * expired. A code that never existed, and one belonging to another app,
     * both read as expired.
     *
     * @return array{status: string, enrolment_id?: string}
     */
    public function getPairingCodeStatus(string $code): array
    {
        return $this->get('/api/v1/sdk/pairing-codes/' . rawurlencode($code));
    }

    /**
     * Poll a pairing code until the user redeems it, then return the resulting
     * enrolment. This is the link half of link-then-push, and it mirrors
     * waitForApproval so that knowing one means knowing the other.
     *
     * $opts:
     *   user_identifier string  REQUIRED -- the identifier the code was minted
     *                           for, used to fetch the enrolment once redeemed.
     *   interval_ms     int     Poll interval (default 2000).
     *   timeout_ms      int     Give up after this long (default 120000).
     *
     * WARNING: this blocks. Never call it from a web request a user is waiting
     * on -- under PHP-FPM it pins a worker process for the whole timeout
     * (default 120 seconds), and a site that puts this on its login path will
     * exhaust its worker pool under modest traffic and go down. Poll
     * getPairingCodeStatus from the browser instead.
     *
     * @param array{user_identifier: string, interval_ms?: int, timeout_ms?: int} $opts
     * @return array<string, mixed> The enrolment.
     * @throws U2AuthException code MISSING_USER_IDENTIFIER if
     *                         opts[user_identifier] is missing or empty;
     *                         PAIRING_CODE_EXPIRED if the code lapses before
     *                         redemption; LINK_TIMEOUT if the deadline passes
     *                         while still pending; ENROLMENT_NOT_FOUND if the
     *                         code is reported redeemed but no matching
     *                         enrolment can be found for user_identifier (the
     *                         redemption and the enrolment lookup are two
     *                         separate backend calls and can disagree).
     */
    public function waitForLink(string $code, array $opts = []): array
    {
        // An empty() check here would reject the literal string "0", which is
        // a legitimate developer-chosen identifier (e.g. a legacy numeric id)
        // -- and empty() has no direct equivalent in Go/Python/Java/C#, so
        // porting this guard naturally would make PHP the only one of six
        // SDKs to reject it. Explicit isset()/'' check instead.
        if (!isset($opts['user_identifier']) || $opts['user_identifier'] === '') {
            throw new U2AuthException(0, 'MISSING_USER_IDENTIFIER', 'waitForLink requires opts[user_identifier]');
        }
        $intervalMs = (int) ($opts['interval_ms'] ?? 2000);
        $timeoutMs = (int) ($opts['timeout_ms'] ?? 120000);
        $deadline = microtime(true) + ($timeoutMs / 1000);

        for (;;) {
            $status = $this->getPairingCodeStatus($code);
            if (($status['status'] ?? '') === 'redeemed') {
                $enrolment = $this->getEnrolment($opts['user_identifier']);
                if ($enrolment === null) {
                    throw new U2AuthException(0, 'ENROLMENT_NOT_FOUND', 'pairing code was redeemed but no enrolment was found for this identifier');
                }
                return $enrolment;
            }
            if (($status['status'] ?? '') === 'expired') {
                throw new U2AuthException(0, 'PAIRING_CODE_EXPIRED', 'pairing code expired before it was redeemed');
            }
            if (microtime(true) >= $deadline) {
                throw new U2AuthException(0, 'LINK_TIMEOUT', 'timed out waiting for the pairing code to be redeemed');
            }
            usleep($intervalMs * 1000);
        }
    }

    /**
     * Poll a push approval until it leaves "pending".
     *
     * WARNING: blocks, exactly as waitForLink does -- under PHP-FPM it pins a
     * worker process for the whole timeout (default 120 seconds). Never call
     * this from a web request a user is waiting on; the WordPress plugin must
     * not use this either -- see waitForLink.
     *
     * @param array{interval_ms?: int, timeout_ms?: int} $opts
     * @return array{approval_id: string, status: string, reason?: string, resolved_at?: string}
     * @throws U2AuthException WAIT_TIMEOUT.
     */
    public function waitForApproval(string $approvalId, array $opts = []): array
    {
        $intervalMs = (int) ($opts['interval_ms'] ?? 2000);
        $timeoutMs = (int) ($opts['timeout_ms'] ?? 120000);
        $deadline = microtime(true) + ($timeoutMs / 1000);

        for (;;) {
            $status = $this->getPushStatus($approvalId);
            if (($status['status'] ?? '') !== 'pending') {
                return $status;
            }
            if (microtime(true) >= $deadline) {
                throw new U2AuthException(0, 'WAIT_TIMEOUT', 'timed out waiting for approval');
            }
            usleep($intervalMs * 1000);
        }
    }

    /**
     * @param array<string, mixed> $body
     * @param array<string, string> $extraHeaders
     * @return array<string, mixed>
     */
    private function post(string $path, array $body, array $extraHeaders = []): array
    {
        $headers = [
            'Authorization: Bearer ' . $this->apiKey,
            'Content-Type: application/json',
        ];
        foreach ($extraHeaders as $name => $value) {
            $headers[] = $name . ': ' . $value;
        }
        $res = $this->transport->send('POST', $this->baseUrl . $path, $headers, json_encode($body));
        return $this->handle($res);
    }

    /** @return array<string, mixed> */
    private function get(string $path): array
    {
        $res = $this->transport->send('GET', $this->baseUrl . $path, [
            'Authorization: Bearer ' . $this->apiKey,
        ], null);
        return $this->handle($res);
    }

    /**
     * DELETE returns 204 with an empty body, which would fail JSON parsing, so
     * it is kept separate from handle().
     */
    private function delete(string $path): void
    {
        $res = $this->transport->send('DELETE', $this->baseUrl . $path, [
            'Authorization: Bearer ' . $this->apiKey,
        ], null);
        if ($res->status >= 200 && $res->status < 300) {
            return;
        }
        throw $this->errorFrom($res);
    }

    /** @return array<string, mixed> */
    private function handle(Http\Response $res): array
    {
        $parsed = json_decode($res->body, true);
        if (!is_array($parsed)) {
            throw new U2AuthException($res->status, 'INVALID_RESPONSE', 'invalid JSON response: ' . $res->body);
        }
        if ($res->status < 200 || $res->status >= 300) {
            throw $this->errorFrom($res);
        }
        return $parsed;
    }

    private function errorFrom(Http\Response $res): U2AuthException
    {
        $parsed = json_decode($res->body, true);
        $code = 'UNKNOWN';
        $message = $res->body !== '' ? $res->body : 'Unknown error';
        if (is_array($parsed) && isset($parsed['error']) && is_array($parsed['error'])) {
            $code = $parsed['error']['code'] ?? $code;
            $message = $parsed['error']['message'] ?? $message;
        }
        return new U2AuthException($res->status, $code, $message);
    }
}

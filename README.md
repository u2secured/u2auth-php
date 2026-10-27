# u2secured/u2auth

PHP SDK for the U2Auth platform — TOTP verification, push tap-to-approve, linked approvals
(pairing codes + enrolments), and signed webhooks.

Part of [U2 Secured Authenticator](https://u2secured.com/authenticator) · [Documentation](https://auth.u2secured.com/developer/docs)

Targets **PHP 7.4** (WordPress's own floor is 7.2.24, and a large share of real installs run 7.4).
Nothing in `src/` may use an 8.x-only construct (enums, readonly properties, constructor
promotion, `match`, union types in signatures, `?->`, named arguments) even though the SDK's own
test suite runs on 8.x and cannot catch a breach.

## Install

```bash
composer require u2secured/u2auth
```

## Quick Start

```php
use U2Secured\U2Auth\U2Auth;

$client = new U2Auth('rka_your_api_key');
$result = $client->verifyTOTP('BASE32SECRET', '123456');
// ['valid' => true]
```

## Push tap-to-approve

```php
$push = $client->requestPush('user@example.com', 'Login from Chrome');
// ['approval_id' => 'ap_1', 'match_number' => 42, 'status' => 'pending', 'expires_at' => '...']

$status = $client->getPushStatus($push['approval_id']);
// ['approval_id' => 'ap_1', 'status' => 'pending' | 'approved' | 'denied' | 'expired']
```

`userIdentifier` matching is case-sensitive and otherwise unnormalised — it's your own key into
your system, not ours, so folding case could silently merge two genuinely different users. A
mismatch throws a `U2AuthException` with code `ENROLMENT_NOT_FOUND` (no enrolment at all for that
identifier), distinct from `NO_DEVICE` (enrolled, but no confirmed device yet).

### Idempotency

```php
$push = $client->requestPush('user@example.com', 'Login from Chrome', [
    'idempotency_key' => $formNonce,
]);
```

While the approval is still pending, repeating the call with the same key returns the original —
same `approval_id`, same `match_number`, no second notification. The key frees itself once the
approval is approved, denied or expired, so a genuine retry after that mints a new request. This is
**not** Stripe-style idempotency: there is no fixed replay window and no stored-response replay.

The key must be stable across the retry, so the SDK cannot invent one for you: a key minted inside
the call is a new key every call and protects nothing. Mint a nonce when the login form is rendered
and carry it in a hidden field — a double-click and a back-then-resubmit both send the same one,
while a fresh page load mints a new one.

Reusing a live key for a different request throws `U2AuthException` with code
`IDEMPOTENCY_KEY_REUSED`; a key over 255 characters throws `INVALID_IDEMPOTENCY_KEY`.

### `$client->waitForApproval(string $approvalId, array $opts = []): array`

Blocking convenience helper that polls `getPushStatus` until the approval leaves `pending`.
`$opts`: `interval_ms` (default `2000`), `timeout_ms` (default `120000`). Throws `U2AuthException`
with code `WAIT_TIMEOUT` if still pending when the deadline passes.

> **This blocks the calling process.** Under PHP-FPM a blocking poll pins a worker for the entire
> timeout — 120 seconds by default. A site that calls `waitForApproval` from the request a user's
> browser is waiting on will exhaust its worker pool under modest traffic and go down. Poll
> `getPushStatus` from the browser (JS `fetch` on an interval, or long-polling your own endpoint)
> instead of blocking a PHP-FPM worker on it.

## Local TOTP

No network call — the developer's own backend already holds the secret, so no round trip is
required to check a code:

```php
use U2Secured\U2Auth\Helpers;

$secret = Helpers::generateSecret();
$uri = Helpers::generateQRCodeURI('MyApp', 'user@example.com', $secret);
$ok = Helpers::validateTOTP($secret, $code); // bool, +/-1 window for clock drift
$codes = Helpers::generateRecoveryCodes(); // 10 unique 8-char codes
```

`Helpers::validateTOTP` runs the same RFC 6238 check the U2 Secured Authenticator backend runs and
returns the same answer, but it does **not** provide the shared brute-force lockout or an entry in
the developer portal's Activity feed that `$client->verifyTOTP()` gives you. Neither call protects
against replay on its own — bind a successful check to a single login attempt.

## Linked approvals

"Linked approvals" is link-then-push: a user links their phone to *your* account once (via a
pairing code), and afterwards you call `requestPush` directly against their `user_identifier` —
no code re-entry required.

```php
// 1. Mint a code and show it to the signed-in user (e.g. as text + a QR code).
$pairing = $client->createPairingCode('user@example.com');
// ['code' => 'af17-b500', 'expires_at' => '2026-09-15T10:10:00Z']

// 2. The user opens the U2 Secured app and redeems the code there. Meanwhile,
//    poll its status from the BROWSER, not from a blocking PHP call --
//    see the waitForLink warning below.
$status = $client->getPairingCodeStatus($pairing['code']);
// ['status' => 'pending' | 'redeemed' | 'expired', 'enrolment_id' => 'en_1']

// 3. Once redeemed, the identifier is linked. From then on, request push
//    directly -- no pairing code involved.
$push = $client->requestPush('user@example.com', 'Login from Chrome');
```

### `$client->getEnrolment(string $userIdentifier): ?array`

Looks up this app's enrolment for one user identifier. **Returns `null` when the user is not
linked — it does not throw.** At login, "this user has not linked a phone" is the normal answer,
not an error; forcing every caller into try/catch on the common path is how integrations end up
wrapping everything in a broad catch and swallowing real errors too. This is deliberately unlike
`deleteEnrolment`, where the absence genuinely is the anomaly and it throws `ENROLMENT_NOT_FOUND`.

```php
$enrolment = $client->getEnrolment('user@example.com');
if ($enrolment === null) {
    // show a "link your phone" prompt
} elseif ($enrolment['push_ready']) {
    $push = $client->requestPush('user@example.com', 'Login from Chrome');
}
```

Returns `array{id, user_identifier, created_at, last_auth_at, last_auth_outcome, push_ready}`.
For an enrolment that has never authenticated, `last_auth_at` and `last_auth_outcome` are both
`null` rather than a zero time / empty string.

### `$client->getPairingCodeStatus(string $code): array`

Reads where a pairing code is in its lifecycle. Returns `array{status, enrolment_id?}`, where
`status` is `pending`, `redeemed` or `expired`. A code that never existed, and one belonging to
another app, both read as `expired`. This is the call the WordPress plugin polls from the browser.

### `$client->waitForLink(string $code, array $opts = []): array`

Blocking convenience helper that mirrors `waitForApproval` — same options shape, same polling
structure — so a developer who has used one can use the other without re-reading the docs. Polls
`getPairingCodeStatus` until the code is redeemed, then fetches and returns the resulting
**enrolment** (not just the status — that's why `user_identifier` is required: the status response
alone doesn't carry enough to look the enrolment up).

`$opts`:

| key | type | default | notes |
|---|---|---|---|
| `user_identifier` | `string` | — | **Required.** The identifier the code was minted for. Throws `U2AuthException` with code `MISSING_USER_IDENTIFIER` if omitted — never silently defaulted. |
| `interval_ms` | `int` | `2000` | Poll interval. |
| `timeout_ms` | `int` | `120000` | Give up after this long. |

Throws `U2AuthException` with code `PAIRING_CODE_EXPIRED` if the code lapses before redemption,
`LINK_TIMEOUT` if the deadline passes while it's still pending — mirroring `waitForApproval`'s
`WAIT_TIMEOUT` — or `ENROLMENT_NOT_FOUND` if the code comes back `redeemed` but no matching
enrolment can be found for `user_identifier`. That last one is rare but reachable: redemption and
the enrolment lookup are two separate backend calls, and they can disagree.

```php
$enrolment = $client->waitForLink($pairing['code'], [
    'user_identifier' => 'user@example.com',
]);
```

> **This blocks the calling process, exactly like `waitForApproval`.** Under PHP-FPM a blocking
> poll pins a worker for the entire timeout — 120 seconds by default. A site that calls
> `waitForLink` from a request a user's browser is waiting on (e.g. directly on a login or account
> page load) will exhaust its worker pool under modest traffic and go down. **The WordPress plugin
> deliberately does not use `waitForLink` or `waitForApproval`** — it polls
> `getPairingCodeStatus` / `getPushStatus` from the browser on an interval instead. Reach for
> `waitForLink` only from something that already owns a dedicated process or long timeout budget
> (a CLI script, a queue worker), never from a normal PHP-FPM request.

## API Reference

### `new U2Auth(string $apiKey, array $opts = [])`

`$opts`:
- `base_url` — override the API base URL (default: `https://auth.u2secured.com`)
- `transport` — an object implementing `U2Secured\U2Auth\Http\Transport`, for tests or custom
  HTTP stacks (default: `U2Secured\U2Auth\Http\CurlTransport`)

### `$client->verifyTOTP(string $secret, string $code): array`

Calls `POST /api/v1/sdk/totp/verify`. Returns `['valid' => bool]`.

### `$client->requestPush(string $userIdentifier, string $context, array $opts = []): array`

Calls `POST /api/v1/sdk/push/request`. `$opts`: `webhook_url?`, `ttl?`, `idempotency_key?` (sent
as the `Idempotency-Key` header, never in the body). Returns
`['approval_id' => ..., 'match_number' => ..., 'status' => ..., 'expires_at' => ...]`.

### `$client->getPushStatus(string $approvalId): array`

Calls `GET /api/v1/sdk/push/{id}/status`. Returns `['approval_id' => ..., 'status' => ...]`.

### `$client->waitForApproval(string $approvalId, array $opts = []): array`

See [Push tap-to-approve](#push-tap-to-approve) above.

### `$client->createPairingCode(string $userIdentifier): array`

Calls `POST /api/v1/sdk/pairing-codes`. Mints a code binding `$userIdentifier` to whichever
account redeems it in the U2 Secured app. Returns `['code' => ..., 'expires_at' => ...]`.

### `$client->getPairingCodeStatus(string $code): array`

See [Linked approvals](#linked-approvals) above.

### `$client->waitForLink(string $code, array $opts = []): array`

See [Linked approvals](#linked-approvals) above.

### `$client->getEnrolment(string $userIdentifier): ?array`

See [Linked approvals](#linked-approvals) above.

### `$client->deleteEnrolment(string $userIdentifier): void`

Calls `DELETE /api/v1/sdk/enrolments`. Removes the link between this app and `$userIdentifier`.
Throws `U2AuthException` with code `ENROLMENT_NOT_FOUND` if there was no such enrolment — unlike
`getEnrolment`, absence here is the anomaly.

### `$client->listEnrolments(array $opts = []): array`

Calls `GET /api/v1/sdk/enrolments`. The app is resolved from the API key — there is no `app_id`
parameter.

`$opts`: `limit?`, `cursor?`, `sort?` (`created_at` | `user_identifier` | `last_auth_at`), `order?`
(`asc` | `desc`), `user_identifier?`. Omitted options are left off the query entirely; `limit <= 0`
is treated as unset too. Returns `['items' => [...], 'next_cursor' => string]`.

```php
$cursor = '';
do {
    $page = $client->listEnrolments(['limit' => 50, 'cursor' => $cursor]);
    foreach ($page['items'] as $e) {
        echo $e['user_identifier'], ' ', $e['last_auth_at'], "\n";
    }
    $cursor = $page['next_cursor'];
} while ($cursor !== '');
```

### `$client->listEnrolmentEvents(string $enrolmentId, array $opts = []): array`

Calls `GET /api/v1/sdk/enrolments/{enrolmentId}/events`. Lists the authentication events recorded
for one enrolment. `$opts`: `limit?`, `cursor?` — same omit-if-unset rules as `listEnrolments`.
An event's `place` is a coarse, city-level location or `null` when no fix was captured.

### Helpers (no API call)

```php
Helpers::generateSecret(int $byteLen = 20): string
Helpers::generateQRCodeURI(string $issuer, string $account, string $secret, array $opts = []): string
Helpers::generateRecoveryCodes(int $count = 10): array
Helpers::generateTOTP(string $secret, int $timestamp, int $digits = 6, int $period = 30): string
Helpers::validateTOTP(string $secret, string $code, ?int $timestamp = null, int $digits = 6, int $period = 30): bool
```

`$opts` for `generateQRCodeURI`: `algorithm?` (default `SHA1`), `digits?` (default `6`), `period?`
(default `30`).

### Error handling

API errors throw `U2Secured\U2Auth\U2AuthException`, with `getStatusCode(): int` and
`getCode(): string` (the U2 error code, e.g. `ENROLMENT_NOT_FOUND` — not the HTTP status).

A genuine network failure (no response at all) is distinguishable from an API error: it throws
`U2AuthException` with status `0` and code `NETWORK_ERROR`, so callers that fail closed can key on
exactly that.

```php
try {
    $client->verifyTOTP($secret, $code);
} catch (\U2Secured\U2Auth\U2AuthException $e) {
    if ($e->getStatusCode() === 0 && $e->getCode() === 'NETWORK_ERROR') {
        // no response reached us -- decide your own fail-open/fail-closed policy
    }
    // $e->getStatusCode(), $e->getCode(), $e->getMessage()
}
```

## Verifying webhooks

```php
use U2Secured\U2Auth\Webhook;

$event = Webhook::verify($rawBody, $signatureHeader, $webhookSecret);
// throws U2AuthException on a bad signature or stale timestamp
// $event['approval_id'], $event['status'], $event['reason'], $event['resolved_at']
```

Pass the **raw request body** (the exact bytes U2 Secured sent), never a value that's been parsed
and re-encoded — JSON re-serialisation (different key order, whitespace, escaping) changes the
bytes and the signature will no longer match even though the payload is "the same" logically. In a
WordPress REST route this means reading the raw body yourself, e.g. `$request->get_body()` (which
wraps `php://input`) — **never** `WP_REST_Request::get_json_params()`, which hands back an
already-decoded (and therefore already re-serialisable-different) array.

The signature is checked before the timestamp: a forged header never gets far enough to have its
timestamp inspected. Throws `U2AuthException` with code `INVALID_SIGNATURE` for a malformed or
mismatched signature, `TIMESTAMP_OUT_OF_TOLERANCE` for a signed timestamp outside the tolerance
window (default 300s, adjustable via the fourth argument), or `INVALID_PAYLOAD` for a validly
signed body that doesn't decode to a JSON object. Handlers should dedupe on `$event['approval_id']`.

## Testing without a network

HTTP goes through an injectable `Transport`, so tests never need a running server:

```php
use U2Secured\U2Auth\Http\Response;
use U2Secured\U2Auth\Http\Transport;
use U2Secured\U2Auth\U2Auth;

final class FakeTransport implements Transport
{
    public function send(string $method, string $url, array $headers, ?string $body): Response
    {
        return new Response(200, json_encode(['valid' => true]));
    }
}

$client = new U2Auth('rka_test', ['transport' => new FakeTransport()]);
```

A `Transport` implementation must **not** throw on a non-2xx status — `U2Auth` maps those to
`U2AuthException` itself, so every U2Secured SDK reports the same error shape regardless of
language.

## Development

```bash
composer install
vendor/bin/phpunit
```

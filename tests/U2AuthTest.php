<?php

declare(strict_types=1);

namespace U2Secured\U2Auth\Tests;

use PHPUnit\Framework\TestCase;
use U2Secured\U2Auth\U2Auth;
use U2Secured\U2Auth\U2AuthException;

final class U2AuthTest extends TestCase
{
    /**
     * The default base URL is a SECURITY boundary, not a convenience.
     *
     * A client built without an explicit base_url sends the caller's rka_ API
     * key to whatever this constant names. It named https://app.u2secured.io
     * for the whole of 0.1.x -- a domain that was never registered, so any
     * stranger could have bought it and collected keys from every integration
     * that took the default. Nothing caught it because every other test in
     * this file passes base_url explicitly, so the constant was exercised by
     * no test at all.
     *
     * This asserts the literal host rather than the constant against itself,
     * which would pass no matter what the constant said.
     */
    public function testDefaultBaseUrlIsTheProductionHost(): void
    {
        $this->assertSame('https://auth.u2secured.com', U2Auth::DEFAULT_BASE_URL);
    }

    /** ...and that a client with no base_url option actually uses it. */
    public function testClientWithNoBaseUrlOptionCallsTheProductionHost(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['valid' => true]);

        (new U2Auth('rka_test', ['transport' => $t]))->verifyTOTP('S3CR3T', '123456');

        $this->assertStringStartsWith(
            'https://auth.u2secured.com',
            $t->lastRequest()['url']
        );
    }

    private function client(FakeTransport $t): U2Auth
    {
        return new U2Auth('rka_test', [
            'base_url' => 'https://example.test',
            'transport' => $t,
        ]);
    }

    public function testVerifyTotpPostsSecretAndCode(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['valid' => true]);

        $result = $this->client($t)->verifyTOTP('MYSECRET', '123456');

        $this->assertTrue($result['valid']);
        $req = $t->lastRequest();
        $this->assertSame('POST', $req['method']);
        $this->assertSame('https://example.test/api/v1/sdk/totp/verify', $req['url']);
        $this->assertContains('Authorization: Bearer rka_test', $req['headers']);
        $this->assertSame(['secret' => 'MYSECRET', 'code' => '123456'], json_decode($req['body'], true));
    }

    public function testApiErrorBecomesException(): void
    {
        $t = new FakeTransport();
        $t->queueJson(404, ['error' => ['code' => 'ENROLMENT_NOT_FOUND', 'message' => 'nope']]);

        try {
            $this->client($t)->verifyTOTP('MYSECRET', '123456');
            $this->fail('expected U2AuthException');
        } catch (U2AuthException $e) {
            $this->assertSame(404, $e->getStatusCode());
            $this->assertSame('ENROLMENT_NOT_FOUND', $e->getCode());
        }
    }

    public function testRequestPushSendsIdempotencyKeyAsAHeader(): void
    {
        $t = new FakeTransport();
        $t->queueJson(201, [
            'approval_id' => 'ap_1',
            'match_number' => 42,
            'status' => 'pending',
            'expires_at' => '2026-09-15T10:00:00Z',
        ]);

        $result = $this->client($t)->requestPush('ada@example.com', 'Login from Chrome', [
            'idempotency_key' => 'nonce-abc',
            'ttl' => 90,
        ]);

        $this->assertSame(42, $result['match_number']);
        $req = $t->lastRequest();
        $this->assertSame('https://example.test/api/v1/sdk/push/request', $req['url']);
        // The key travels as a header, never in the body.
        $this->assertContains('Idempotency-Key: nonce-abc', $req['headers']);
        $body = json_decode($req['body'], true);
        $this->assertArrayNotHasKey('idempotency_key', $body);
        $this->assertSame(90, $body['ttl']);
        $this->assertSame('ada@example.com', $body['user_identifier']);
    }

    public function testRequestPushOmitsUnsetOptions(): void
    {
        $t = new FakeTransport();
        $t->queueJson(201, ['approval_id' => 'ap_1', 'match_number' => 1, 'status' => 'pending', 'expires_at' => 'x']);

        $this->client($t)->requestPush('ada@example.com', 'Login');

        $body = json_decode($t->lastRequest()['body'], true);
        $this->assertSame(['user_identifier' => 'ada@example.com', 'context' => 'Login'], $body);
    }

    public function testGetPushStatusReadsTheApproval(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['approval_id' => 'ap_1', 'status' => 'approved']);

        $status = $this->client($t)->getPushStatus('ap_1');

        $this->assertSame('approved', $status['status']);
        $this->assertSame('GET', $t->lastRequest()['method']);
        $this->assertSame('https://example.test/api/v1/sdk/push/ap_1/status', $t->lastRequest()['url']);
    }

    public function testCreatePairingCodeReturnsTheCode(): void
    {
        $t = new FakeTransport();
        $t->queueJson(201, ['code' => 'af17-b500', 'expires_at' => '2026-09-15T10:10:00Z']);

        $pc = $this->client($t)->createPairingCode('ada@example.com');

        $this->assertSame('af17-b500', $pc['code']);
        $this->assertSame('https://example.test/api/v1/sdk/pairing-codes', $t->lastRequest()['url']);
    }

    /**
     * The identifier travels as a query parameter, not a path segment: it is an
     * arbitrary developer-chosen string and one containing "/" breaks path
     * routing even percent-encoded.
     */
    public function testDeleteEnrolmentPutsTheIdentifierInTheQuery(): void
    {
        $t = new FakeTransport();
        $t->queue(204, '');

        $this->client($t)->deleteEnrolment('a/b@example.com');

        $req = $t->lastRequest();
        $this->assertSame('DELETE', $req['method']);
        $this->assertSame(
            'https://example.test/api/v1/sdk/enrolments?user_identifier=a%2Fb%40example.com',
            $req['url']
        );
    }

    public function testListEnrolmentsOmitsUnsetOptions(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['items' => [], 'next_cursor' => '']);

        $this->client($t)->listEnrolments(['limit' => 0, 'cursor' => '']);

        // limit <= 0 is treated as unset, matching every other SDK.
        $this->assertSame('https://example.test/api/v1/sdk/enrolments', $t->lastRequest()['url']);
    }

    /**
     * A zero-only test is not enough to pin this guard. `!empty($opts['limit'])`
     * alone already omits 0, so the `&& $opts['limit'] > 0` clause reads as
     * redundant to anyone tidying this method -- and it is the only thing
     * stopping a negative limit being sent to the server, which would answer
     * INVALID_LIMIT. PHP is the reference every future port is read from, so
     * the negative case is pinned here explicitly.
     */
    public function testListEnrolmentsOmitsANegativeLimitSameAsZero(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['items' => [], 'next_cursor' => '']);

        $this->client($t)->listEnrolments(['limit' => -1]);

        $this->assertSame('https://example.test/api/v1/sdk/enrolments', $t->lastRequest()['url']);
    }

    public function testListEnrolmentsEncodesUserIdentifierInQuery(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['items' => [], 'next_cursor' => '']);

        $this->client($t)->listEnrolments(['user_identifier' => 'a/b@example.com']);

        $this->assertStringContainsString(
            'user_identifier=a%2Fb%40example.com',
            $t->lastRequest()['url']
        );
    }

    /**
     * user_identifier is an arbitrary developer-chosen string, so the literal
     * "0" is a legitimate value (e.g. a legacy numeric id) -- empty() would
     * treat it as unset and silently drop the filter, matching whichever
     * enrolment happens to come back first instead of the one asked for.
     * This is the same class of bug fixed in waitForLink's
     * MISSING_USER_IDENTIFIER guard, found while auditing for it.
     */
    public function testListEnrolmentsKeepsUserIdentifierFilterWhenItIsTheStringZero(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['items' => [], 'next_cursor' => '']);

        $this->client($t)->listEnrolments(['user_identifier' => '0']);

        $this->assertStringContainsString('user_identifier=0', $t->lastRequest()['url']);
    }

    public function testListEnrolmentEventsReadsTheEvents(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, [
            'items' => [['id' => 'evt_1', 'kind' => 'auth', 'outcome' => 'success']],
            'next_cursor' => 'abc',
        ]);

        // The space in the id would leak into the path unescaped if
        // rawurlencode were dropped from the enrolment id segment.
        $result = $this->client($t)->listEnrolmentEvents('en 1');

        $req = $t->lastRequest();
        $this->assertSame('GET', $req['method']);
        $this->assertSame('https://example.test/api/v1/sdk/enrolments/en%201/events', $req['url']);
        $this->assertSame([['id' => 'evt_1', 'kind' => 'auth', 'outcome' => 'success']], $result['items']);
        $this->assertSame('abc', $result['next_cursor']);
    }

    public function testListEnrolmentEventsIncludesLimitAndCursor(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['items' => [], 'next_cursor' => '']);

        $this->client($t)->listEnrolmentEvents('en_1', ['limit' => 10, 'cursor' => 'xyz']);

        $url = $t->lastRequest()['url'];
        $this->assertStringContainsString('limit=10', $url);
        $this->assertStringContainsString('cursor=xyz', $url);
    }

    public function testListEnrolmentEventsOmitsUnsetOptions(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['items' => [], 'next_cursor' => '']);

        $this->client($t)->listEnrolmentEvents('en_1', ['limit' => 0, 'cursor' => '']);

        // limit <= 0 is treated as unset, matching every other SDK.
        $this->assertSame('https://example.test/api/v1/sdk/enrolments/en_1/events', $t->lastRequest()['url']);
    }

    /**
     * Same reasoning as testListEnrolmentsOmitsANegativeLimitSameAsZero: the
     * `&& > 0` half of this method's guard is what excludes a negative limit,
     * and a zero-only test would pass without it.
     */
    public function testListEnrolmentEventsOmitsANegativeLimitSameAsZero(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['items' => [], 'next_cursor' => '']);

        $this->client($t)->listEnrolmentEvents('en_1', ['limit' => -1]);

        $this->assertSame('https://example.test/api/v1/sdk/enrolments/en_1/events', $t->lastRequest()['url']);
    }

    /**
     * Not linked is the NORMAL case at login, so it is null rather than an
     * exception. Deliberately unlike deleteEnrolment, where the absence is the
     * anomaly and ENROLMENT_NOT_FOUND is right.
     */
    public function testGetEnrolmentReturnsNullWhenNotLinked(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['items' => [], 'next_cursor' => '']);

        $this->assertNull($this->client($t)->getEnrolment('nobody@example.com'));
    }

    public function testGetEnrolmentReturnsTheSingleMatch(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, [
            'items' => [[
                'id' => 'en_1',
                'user_identifier' => 'ada@example.com',
                'created_at' => '2026-09-15T09:00:00Z',
                'last_auth_at' => null,
                'last_auth_outcome' => null,
                'push_ready' => true,
            ]],
            'next_cursor' => '',
        ]);

        $e = $this->client($t)->getEnrolment('ada@example.com');

        $this->assertSame('en_1', $e['id']);
        $this->assertTrue($e['push_ready']);
        $this->assertStringContainsString('user_identifier=ada%40example.com', $t->lastRequest()['url']);
    }

    public function testGetPairingCodeStatusReadsTheCode(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['status' => 'redeemed', 'enrolment_id' => 'en_1']);

        $status = $this->client($t)->getPairingCodeStatus('af17-b500');

        $this->assertSame('redeemed', $status['status']);
        $this->assertSame('https://example.test/api/v1/sdk/pairing-codes/af17-b500', $t->lastRequest()['url']);
    }

    public function testWaitForLinkPollsUntilRedeemed(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['status' => 'pending']);
        $t->queueJson(200, ['status' => 'redeemed', 'enrolment_id' => 'en_1']);
        $t->queueJson(200, [
            'items' => [[
                'id' => 'en_1',
                'user_identifier' => 'ada@example.com',
                'created_at' => '2026-09-15T09:00:00Z',
                'last_auth_at' => null,
                'last_auth_outcome' => null,
                'push_ready' => false,
            ]],
            'next_cursor' => '',
        ]);

        $e = $this->client($t)->waitForLink('af17-b500', [
            'interval_ms' => 1,
            'timeout_ms' => 5000,
            'user_identifier' => 'ada@example.com',
        ]);

        $this->assertSame('en_1', $e['id']);
        $this->assertCount(3, $t->requests);
    }

    /**
     * Redemption and the enrolment lookup are two separate backend calls and
     * can disagree -- this is the same defect class already fixed once in
     * Webhook::verify (a null returned from a non-nullable-returning path
     * caused an uncaught TypeError). Pin it so it cannot silently regress.
     */
    public function testWaitForLinkThrowsEnrolmentNotFoundWhenRedeemedButNoEnrolment(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['status' => 'redeemed', 'enrolment_id' => 'en_1']);
        $t->queueJson(200, ['items' => [], 'next_cursor' => '']);

        try {
            $this->client($t)->waitForLink('af17-b500', ['interval_ms' => 1, 'user_identifier' => 'ada@example.com']);
            $this->fail('expected U2AuthException');
        } catch (U2AuthException $e) {
            $this->assertSame('ENROLMENT_NOT_FOUND', $e->getCode());
        }
    }

    public function testWaitForLinkThrowsWhenTheCodeExpires(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['status' => 'expired']);

        try {
            $this->client($t)->waitForLink('af17-b500', ['interval_ms' => 1, 'user_identifier' => 'ada@example.com']);
            $this->fail('expected U2AuthException');
        } catch (U2AuthException $e) {
            $this->assertSame('PAIRING_CODE_EXPIRED', $e->getCode());
        }
    }

    public function testWaitForLinkTimesOut(): void
    {
        $t = new FakeTransport();
        for ($i = 0; $i < 5; $i++) {
            $t->queueJson(200, ['status' => 'pending']);
        }

        try {
            $this->client($t)->waitForLink('af17-b500', [
                'interval_ms' => 1,
                'timeout_ms' => 3,
                'user_identifier' => 'ada@example.com',
            ]);
            $this->fail('expected U2AuthException');
        } catch (U2AuthException $e) {
            $this->assertSame('LINK_TIMEOUT', $e->getCode());
        }
    }

    public function testWaitForLinkRequiresUserIdentifier(): void
    {
        $t = new FakeTransport();

        try {
            $this->client($t)->waitForLink('af17-b500');
            $this->fail('expected U2AuthException');
        } catch (U2AuthException $e) {
            $this->assertSame('MISSING_USER_IDENTIFIER', $e->getCode());
        }
    }

    public function testWaitForApprovalReturnsOnceNoLongerPending(): void
    {
        $t = new FakeTransport();
        $t->queueJson(200, ['approval_id' => 'ap_1', 'status' => 'pending']);
        $t->queueJson(200, ['approval_id' => 'ap_1', 'status' => 'approved']);

        $status = $this->client($t)->waitForApproval('ap_1', ['interval_ms' => 1]);

        $this->assertSame('approved', $status['status']);
        $this->assertCount(2, $t->requests);
    }

    public function testWaitForApprovalTimesOut(): void
    {
        $t = new FakeTransport();
        for ($i = 0; $i < 5; $i++) {
            $t->queueJson(200, ['approval_id' => 'ap_1', 'status' => 'pending']);
        }

        try {
            $this->client($t)->waitForApproval('ap_1', ['interval_ms' => 1, 'timeout_ms' => 3]);
            $this->fail('expected U2AuthException');
        } catch (U2AuthException $e) {
            $this->assertSame('WAIT_TIMEOUT', $e->getCode());
        }
    }
}

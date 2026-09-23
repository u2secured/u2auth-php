<?php

declare(strict_types=1);

namespace U2Secured\U2Auth;

/**
 * TOTP generation/validation, secret + recovery-code generation, and the
 * otpauth QR URI. Ported from `node/src/helpers.ts` - match its behaviour,
 * not just its shape, and see that file for the fuller rationale comments.
 */
final class Helpers
{
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Charset for recovery codes. NOTE: this is deliberately NOT the base32
     * alphabet above - it matches node's generateRecoveryCodes exactly
     * (uppercase letters + digits), because these codes are shown to end
     * users and stored hashed; a different alphabet per SDK would be
     * user-visible and, once issued, could not be quietly changed.
     */
    private const RECOVERY_CODE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

    /**
     * Generate a cryptographically random base32-encoded TOTP secret.
     */
    public static function generateSecret(int $byteLen = 20): string
    {
        return self::toBase32(random_bytes($byteLen));
    }

    /**
     * Build an otpauth://totp/... URI for QR code display.
     *
     * @param array{algorithm?: string, digits?: int, period?: int} $opts
     */
    public static function generateQRCodeURI(string $issuer, string $account, string $secret, array $opts = []): string
    {
        $algorithm = isset($opts['algorithm']) ? $opts['algorithm'] : 'SHA1';
        $digits = isset($opts['digits']) ? $opts['digits'] : 6;
        $period = isset($opts['period']) ? $opts['period'] : 30;

        $label = rawurlencode($issuer) . ':' . rawurlencode($account);
        // Default (RFC1738) encoding deliberately: it encodes spaces as `+`,
        // matching node's URLSearchParams, python's urlencode and go's
        // url.Values.Encode() - all three shipped SDKs agree on `+`. Do NOT
        // pass PHP_QUERY_RFC3986 here; that switches spaces to `%20` and
        // makes PHP the one SDK whose otpauth URI differs from the rest.
        $params = http_build_query([
            'secret' => $secret,
            'issuer' => $issuer,
            'algorithm' => $algorithm,
            'digits' => (string) $digits,
            'period' => (string) $period,
        ], '', '&');

        return 'otpauth://totp/' . $label . '?' . $params;
    }

    /**
     * Generate count random 8-character alphanumeric recovery codes.
     *
     * node has no uniqueness check (it just draws count independent random
     * codes). We add one: these codes are stored hashed and consumed once,
     * so an accidental repeat would let one code be redeemed twice - a real,
     * if improbable, defect. The loop costs nothing at this size.
     *
     * @return array<int, string>
     */
    public static function generateRecoveryCodes(int $count = 10): array
    {
        $charsetLen = strlen(self::RECOVERY_CODE_CHARSET);
        $codes = [];
        $seen = [];
        while (count($codes) < $count) {
            $buf = random_bytes(8);
            $code = '';
            for ($j = 0; $j < 8; $j++) {
                $code .= self::RECOVERY_CODE_CHARSET[ord($buf[$j]) % $charsetLen];
            }
            if (isset($seen[$code])) {
                continue;
            }
            $seen[$code] = true;
            $codes[] = $code;
        }
        return $codes;
    }

    /**
     * Compute the TOTP code for a secret at a given instant (RFC 6238).
     * Exposed mainly so tests can drive a fixed clock; most callers want
     * {@see validateTOTP}.
     *
     * @param int $timestamp Unix time in seconds.
     */
    public static function generateTOTP(string $secret, int $timestamp, int $digits = 6, int $period = 30): string
    {
        $counter = intdiv($timestamp, $period);
        $counterBytes = pack('J', $counter);

        $mac = hash_hmac('sha1', $counterBytes, self::fromBase32($secret), true);
        $offset = ord($mac[strlen($mac) - 1]) & 0x0f;
        $truncated = ((ord($mac[$offset]) & 0x7f) << 24)
            | ((ord($mac[$offset + 1]) & 0xff) << 16)
            | ((ord($mac[$offset + 2]) & 0xff) << 8)
            | (ord($mac[$offset + 3]) & 0xff);

        $code = (string) ($truncated % (10 ** $digits));
        return str_pad($code, $digits, '0', STR_PAD_LEFT);
    }

    /**
     * Verify a TOTP code locally, without a network call.
     *
     * This runs the same RFC 6238 check the U2 Secured Authenticator backend
     * runs, including the +/-1 window tolerance for clock drift, and returns
     * the same answer. Prefer it when a login must not depend on a third
     * party being reachable: the developer's backend already holds the
     * secret, so no round trip is required to check a code.
     *
     * What it does NOT provide, and `client.verifyTOTP()` does:
     *   - the shared brute-force lockout, which spans all of your backend instances
     *   - an entry in the Activity feed of the developer portal
     *
     * Neither call protects against replay on its own - a code stays valid
     * for its whole window. Bind a successful check to a single login attempt.
     *
     * @param int|null $timestamp Unix time in seconds; defaults to now.
     */
    public static function validateTOTP(string $secret, string $code, ?int $timestamp = null, int $digits = 6, int $period = 30): bool
    {
        $now = $timestamp !== null ? $timestamp : time();
        $supplied = trim($code);
        $ok = false;
        for ($delta = -1; $delta <= 1; $delta++) {
            $candidate = self::generateTOTP($secret, $now + ($delta * $period), $digits, $period);
            // Compare every window rather than short-circuiting, and use a
            // length-checked constant-time compare, so neither the matching
            // window nor the number of correct digits is observable through
            // timing.
            if (strlen($candidate) === strlen($supplied) && hash_equals($candidate, $supplied)) {
                $ok = true;
            }
        }
        return $ok;
    }

    private static function toBase32(string $buf): string
    {
        $bits = 0;
        $value = 0;
        $output = '';
        $len = strlen($buf);

        for ($i = 0; $i < $len; $i++) {
            $value = ($value << 8) | ord($buf[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $output .= self::BASE32_ALPHABET[($value >> ($bits - 5)) & 31];
                $bits -= 5;
            }
        }
        if ($bits > 0) {
            $output .= self::BASE32_ALPHABET[($value << (5 - $bits)) & 31];
        }
        return $output;
    }

    private static function fromBase32(string $secret): string
    {
        $clean = rtrim(strtoupper(trim($secret)), '=');
        $bits = 0;
        $value = 0;
        $out = '';
        $len = strlen($clean);

        for ($i = 0; $i < $len; $i++) {
            $idx = strpos(self::BASE32_ALPHABET, $clean[$i]);
            if ($idx === false) {
                continue;
            }
            $value = ($value << 5) | $idx;
            $bits += 5;
            if ($bits >= 8) {
                $out .= chr(($value >> ($bits - 8)) & 0xff);
                $bits -= 8;
            }
        }
        return $out;
    }
}

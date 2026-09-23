<?php

declare(strict_types=1);

namespace U2Secured\U2Auth\Tests;

use PHPUnit\Framework\TestCase;
use U2Secured\U2Auth\Helpers;

final class HelpersTest extends TestCase
{
    /**
     * The shared vectors are the contract between every SDK and the backend.
     * A port that passes these agrees with the reference implementation; one
     * that merely looks similar does not.
     */
    public function testTotpMatchesSharedVectors(): void
    {
        $path = __DIR__ . '/../../testvectors/totp.json';
        $vectors = json_decode(file_get_contents($path), true);
        $this->assertIsArray($vectors, 'could not read ' . $path);

        foreach ($vectors['cases'] as $case) {
            $got = Helpers::validateTOTP($case['secret'], $case['code'], $case['time']);
            $this->assertSame(
                $case['valid'],
                $got,
                sprintf('vector "%s": validateTOTP returned %s', $case['name'], var_export($got, true))
            );
        }
    }

    public function testGenerateTotpMatchesSharedVectors(): void
    {
        $path = __DIR__ . '/../../testvectors/totp.json';
        $vectors = json_decode(file_get_contents($path), true);

        foreach ($vectors['cases'] as $case) {
            if ($case['name'] !== 'current window') {
                continue;
            }
            $this->assertSame($case['code'], Helpers::generateTOTP($case['secret'], $case['time']));
        }
    }

    public function testRecoveryCodesAreUniqueAndWellFormed(): void
    {
        $codes = Helpers::generateRecoveryCodes(10);
        $this->assertCount(10, $codes);
        $this->assertCount(10, array_unique($codes), 'recovery codes must not repeat');
        foreach ($codes as $code) {
            // Matches node's charset exactly: uppercase letters + digits, 8
            // characters. Not lowercase hex - these are shown to end users and
            // must be identical in format across every SDK.
            $this->assertMatchesRegularExpression('/^[A-Z0-9]{8}$/', $code);
        }
    }

    public function testQrCodeUriCarriesIssuerAndSecret(): void
    {
        $uri = Helpers::generateQRCodeURI('U2 Secured', 'ada@example.com', 'JBSWY3DPEHPK3PXP');
        $this->assertStringStartsWith('otpauth://totp/', $uri);
        $this->assertStringContainsString('secret=JBSWY3DPEHPK3PXP', $uri);
        $this->assertStringContainsString('issuer=U2+Secured', $uri);
    }
}

<?php

namespace Druidfi\AltchaSymfony\Tests\Service;

use Druidfi\AltchaSymfony\Service\AltchaService;
use PHPUnit\Framework\TestCase;

class AltchaServiceTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Factory helper
    // -------------------------------------------------------------------------

    private function makeService(
        string $hmacKey = 'test-hmac-key',
        ?string $sentinelUrl = null,
        ?string $sentinelVerifyUrl = null,
        ?string $sentinelApiKey = null,
        ?string $sentinelApiSecret = null,
        ?string $cost = null,
    ): AltchaService {
        return new AltchaService($hmacKey, $sentinelUrl, $sentinelVerifyUrl, $sentinelApiKey, $sentinelApiSecret, $cost);
    }

    // -------------------------------------------------------------------------
    // isSentinel()
    // -------------------------------------------------------------------------

    public function testIsSentinelReturnsFalseWhenUrlIsNull(): void
    {
        $this->assertFalse($this->makeService()->isSentinel());
    }

    public function testIsSentinelReturnsFalseWhenUrlIsEmpty(): void
    {
        $this->assertFalse($this->makeService(sentinelUrl: '')->isSentinel());
    }

    public function testIsSentinelReturnsTrueWhenUrlIsSet(): void
    {
        $this->assertTrue(
            $this->makeService(sentinelUrl: 'https://eu.altcha.org/api/v1/challenge?apiKey=abc')->isSentinel()
        );
    }

    // -------------------------------------------------------------------------
    // getChallengeUrl()
    // -------------------------------------------------------------------------

    public function testGetChallengeUrlReturnsSentinelUrlInSentinelMode(): void
    {
        $service = $this->makeService(sentinelUrl: 'https://eu.altcha.org/api/v1/challenge?apiKey=abc');

        $this->assertSame(
            'https://eu.altcha.org/api/v1/challenge?apiKey=abc',
            $service->getChallengeUrl('/altcha/challenge'),
        );
    }

    public function testGetChallengeUrlReturnsLocalUrlInSelfHostedMode(): void
    {
        $this->assertSame(
            '/altcha/challenge',
            $this->makeService()->getChallengeUrl('/altcha/challenge'),
        );
    }

    public function testGetChallengeUrlAppendsApiKeyToBaseUrl(): void
    {
        $service = $this->makeService(
            sentinelUrl: 'https://eu.altcha.org/api/v1/challenge',
            sentinelApiKey: 'mykey',
        );

        $this->assertSame(
            'https://eu.altcha.org/api/v1/challenge?apiKey=mykey',
            $service->getChallengeUrl('/altcha/challenge'),
        );
    }

    public function testGetChallengeUrlAppendsApiKeyWhenUrlAlreadyHasQueryString(): void
    {
        $service = $this->makeService(
            sentinelUrl: 'https://eu.altcha.org/api/v1/challenge?foo=bar',
            sentinelApiKey: 'mykey',
        );

        $this->assertSame(
            'https://eu.altcha.org/api/v1/challenge?foo=bar&apiKey=mykey',
            $service->getChallengeUrl('/altcha/challenge'),
        );
    }

    public function testGetChallengeUrlIgnoresEmptyApiKey(): void
    {
        $service = $this->makeService(
            sentinelUrl: 'https://eu.altcha.org/api/v1/challenge',
            sentinelApiKey: '',
        );

        $this->assertSame(
            'https://eu.altcha.org/api/v1/challenge',
            $service->getChallengeUrl('/altcha/challenge'),
        );
    }

    // -------------------------------------------------------------------------
    // resolveCost() — tested via ReflectionMethod (private method)
    // -------------------------------------------------------------------------

    /** @dataProvider costProvider */
    public function testResolveCost(?string $input, int $expected): void
    {
        $service = $this->makeService(cost: $input);
        $method = new \ReflectionMethod($service, 'resolveCost');

        $this->assertSame($expected, $method->invoke($service));
    }

    public static function costProvider(): array
    {
        return [
            'null uses default'         => [null,    50000],
            'empty string uses default' => ['',      50000],
            'zero uses default'         => ['0',     50000],
            'negative uses default'     => ['-5000', 50000],
            'non-numeric uses default'  => ['abc',   50000],
            'valid cost is used'        => ['20000', 20000],
            'large cost is used'        => ['200000', 200000],
        ];
    }

    // -------------------------------------------------------------------------
    // verify() — self-hosted mode, malformed payloads
    // -------------------------------------------------------------------------

    public function testVerifyReturnsFalseForPlainString(): void
    {
        $this->assertFalse($this->makeService()->verify('not-a-valid-payload'));
    }

    public function testVerifyReturnsFalseForEmptyString(): void
    {
        $this->assertFalse($this->makeService()->verify(''));
    }

    public function testVerifyReturnsFalseForValidBase64ButInvalidJson(): void
    {
        // base64 decodes successfully but JSON parse fails → library throws → caught → false
        $this->assertFalse($this->makeService()->verify(base64_encode('not-json')));
    }

    public function testVerifyReturnsFalseForRandomBytes(): void
    {
        $this->assertFalse($this->makeService()->verify(base64_encode(random_bytes(32))));
    }

    // -------------------------------------------------------------------------
    // deriveSentinelVerifyUrl() — tested via ReflectionMethod (private method)
    // -------------------------------------------------------------------------

    public function testDeriveSentinelVerifyUrlBuildsCorrectUrl(): void
    {
        $service = $this->makeService(sentinelUrl: 'https://eu.altcha.org/v1/challenge?apiKey=abc');
        $method = new \ReflectionMethod($service, 'deriveSentinelVerifyUrl');

        $this->assertSame(
            'https://eu.altcha.org/v1/verify/signature',
            $method->invoke($service),
        );
    }

    public function testDeriveSentinelVerifyUrlStripsPortFromPath(): void
    {
        // Port is part of the host component — should not appear in the derived path
        $service = $this->makeService(sentinelUrl: 'https://my-sentinel.example.com/v1/challenge?apiKey=abc');
        $method = new \ReflectionMethod($service, 'deriveSentinelVerifyUrl');

        $this->assertSame(
            'https://my-sentinel.example.com/v1/verify/signature',
            $method->invoke($service),
        );
    }

    public function testDeriveSentinelVerifyUrlThrowsForRelativeUrl(): void
    {
        // A string that passes isSentinel() (non-empty) but has no scheme/host
        $service = $this->makeService(sentinelUrl: 'not-an-absolute-url');
        $method = new \ReflectionMethod($service, 'deriveSentinelVerifyUrl');

        $this->expectException(\InvalidArgumentException::class);
        $method->invoke($service);
    }
}

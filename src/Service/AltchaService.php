<?php

namespace Druidfi\AltchaSymfony\Service;

use AltchaOrg\Altcha\Algorithm\Pbkdf2;
use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\Challenge;
use AltchaOrg\Altcha\CreateChallengeOptions;
use AltchaOrg\Altcha\Sentinel;
use AltchaOrg\Altcha\VerifyServerOptions;
use AltchaOrg\Altcha\VerifySolutionOptions;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Handles Altcha CAPTCHA challenge creation and solution verification.
 *
 * Two modes are supported:
 *   - Self-hosted: challenges are generated and verified locally using HMAC + PBKDF2.
 *                  No external network calls. Requires ALTCHA_HMAC_KEY.
 *   - Sentinel:    challenge URL and verification are delegated to Altcha's cloud/sentinel API.
 *                  Activated by setting ALTCHA_SENTINEL_URL to a non-empty value.
 */
class AltchaService
{
    private readonly Altcha $altcha;

    public function __construct(
        #[Autowire(env: 'ALTCHA_HMAC_KEY')]
        private readonly string $hmacKey,
        #[Autowire(value: '%env(default::ALTCHA_SENTINEL_URL)%')]
        private readonly ?string $sentinelUrl = null,
        #[Autowire(value: '%env(default::ALTCHA_SENTINEL_VERIFY_URL)%')]
        private readonly ?string $sentinelVerifyUrl = null,
        #[Autowire(value: '%env(default::ALTCHA_SENTINEL_API_KEY)%')]
        private readonly ?string $sentinelApiKey = null,
        #[Autowire(value: '%env(default::ALTCHA_SENTINEL_API_SECRET)%')]
        private readonly ?string $sentinelApiSecret = null,
        #[Autowire(value: '%env(default::ALTCHA_COST)%')]
        private readonly ?string $cost = null,
    ) {
        $this->altcha = new Altcha(hmacSignatureSecret: $this->hmacKey);
    }

    public function isSentinel(): bool
    {
        return $this->sentinelUrl !== null && $this->sentinelUrl !== '';
    }

    /**
     * Returns the challenge URL for the altcha-widget.
     * Always a URL (never inline JSON) so self-hosted and sentinel/cloud both work.
     */
    public function getChallengeUrl(string $localUrl): string
    {
        if (!$this->isSentinel()) {
            return $localUrl;
        }

        $url = $this->normalizeSentinelChallengeUrl($this->sentinelUrl);

        // Append apiKey as a query parameter if provided separately.
        // This allows ALTCHA_SENTINEL_URL to be a plain base URL and
        // ALTCHA_SENTINEL_API_KEY to be stored as a separate secret in the vault.
        if ($this->sentinelApiKey !== null && $this->sentinelApiKey !== '') {
            $separator = str_contains($url, '?') ? '&' : '?';
            return $url . $separator . 'apiKey=' . urlencode($this->sentinelApiKey);
        }

        return $url;
    }

    /**
     * Ensures the sentinel URL points to the challenge endpoint.
     * If the URL has no path (or just "/"), appends "/v1/challenge" so that
     * a plain base URL like "https://eu.altcha.org" works out of the box.
     */
    private function normalizeSentinelChallengeUrl(string $url): string
    {
        $path = parse_url($url, PHP_URL_PATH) ?? '/';

        if ($path === '' || $path === '/') {
            return rtrim($url, '/') . '/v1/challenge';
        }

        return $url;
    }

    /**
     * Creates a new proof-of-work challenge.
     *
     * Cost is controlled by ALTCHA_COST (default 50 000 PBKDF2 iterations).
     * Higher values increase bot resistance but also increase solve time for real users.
     * Challenges expire after 10 minutes to prevent replay attacks.
     */
    public function createChallenge(): Challenge
    {
        return $this->altcha->createChallenge(new CreateChallengeOptions(
            algorithm: new Pbkdf2(),
            cost: $this->resolveCost(),
            expiresAt: time() + 600,
        ));
    }

    /**
     * Verifies a payload submitted by the altcha-widget.
     *
     * In self-hosted mode: HMAC + PBKDF2 verification happens locally, no network call.
     * In sentinel mode: payload is forwarded to the Sentinel API for verification.
     *
     * Returns false on any verification failure, malformed payload, or network error
     * so callers always receive a bool and never a thrown exception.
     */
    public function verify(string $payload): bool
    {
        if ($this->isSentinel()) {
            $verifyUrl = ($this->sentinelVerifyUrl !== null && $this->sentinelVerifyUrl !== '')
                ? $this->sentinelVerifyUrl
                : $this->deriveSentinelVerifyUrl();

            $secret = ($this->sentinelApiSecret !== null && $this->sentinelApiSecret !== '')
                ? $this->sentinelApiSecret
                : null;

            try {
                $result = Sentinel::verify(new VerifyServerOptions(
                    payload: $payload,
                    url: $verifyUrl,
                    secret: $secret,
                ));
            } catch (\Throwable) {
                // Network errors or sentinel API failures return false so the form shows
                // a CAPTCHA validation error instead of throwing a 500.
                return false;
            }

            return $result->verified;
        }

        try {
            $result = $this->altcha->verifySolution(new VerifySolutionOptions(
                payload: $payload,
                algorithm: new Pbkdf2(),
            ));
        } catch (\Throwable) {
            // Malformed or tampered payloads (bad base64, invalid JSON) cause the library to throw.
            // Treat as verification failure rather than propagating a 500.
            return false;
        }

        return $result->verified;
    }

    /**
     * Resolves the PBKDF2 cost from ALTCHA_COST, falling back to 50 000.
     * Non-numeric and non-positive values are ignored and the default is used instead.
     */
    private function resolveCost(): int
    {
        if ($this->cost !== null && $this->cost !== '') {
            $parsed = (int) $this->cost;
            if ($parsed > 0) {
                return $parsed;
            }
        }

        return 50000;
    }

    /**
     * Derives a verify URL from the sentinel challenge URL as a fallback.
     * e.g. https://eu.altcha.org/v1/challenge?apiKey=xxx -> https://eu.altcha.org/v1/verify/signature
     *      https://eu.altcha.org (plain base URL)         -> https://eu.altcha.org/v1/verify/signature
     *
     * Only safe to call when isSentinel() is true (sentinelUrl is guaranteed non-empty).
     */
    private function deriveSentinelVerifyUrl(): string
    {
        $parsed = parse_url($this->sentinelUrl);

        if (!is_array($parsed) || empty($parsed['scheme']) || empty($parsed['host'])) {
            throw new \InvalidArgumentException('ALTCHA_SENTINEL_URL is not a valid absolute URL — check your environment configuration.');
        }

        $path = $parsed['path'] ?? '';

        // Derive the verify path from the challenge path by replacing /challenge with /verify/signature.
        // Falls back to /v1/verify/signature for plain base URLs (no path).
        if ($path !== '' && $path !== '/' && str_ends_with($path, '/challenge')) {
            $verifyPath = substr($path, 0, -strlen('challenge')) . 'verify/signature';
        } else {
            $verifyPath = '/v1/verify/signature';
        }

        return sprintf('%s://%s%s', $parsed['scheme'], $parsed['host'], $verifyPath);
    }
}

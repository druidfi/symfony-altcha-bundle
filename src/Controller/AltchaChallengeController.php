<?php

namespace Druidfi\AltchaSymfony\Controller;

use Druidfi\AltchaSymfony\Service\AltchaService;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Serves proof-of-work challenges for self-hosted mode.
 *
 * In sentinel mode the widget fetches challenges directly from the Sentinel API,
 * so this endpoint is never called — but it remains registered and harmless.
 * Ensure this route is publicly accessible (no firewall restriction).
 */
class AltchaChallengeController
{
    /** Maximum challenge requests per IP within the rate-limit window. */
    private const RATE_LIMIT = 30;

    /** Rate-limit window in seconds. */
    private const RATE_WINDOW = 60;

    public function __construct(
        private readonly AltchaService $altchaService,
        private readonly RequestStack $requestStack,
        #[Autowire(service: 'cache.app')]
        private readonly CacheItemPoolInterface $cache,
    ) {}

    #[Route('/altcha/challenge', name: 'altcha_challenge', methods: ['GET'])]
    public function __invoke(): Response
    {
        $ip = $this->requestStack->getMainRequest()?->getClientIp() ?? 'unknown';

        if ($this->isRateLimited($ip)) {
            return new JsonResponse(
                ['error' => 'Too many requests.'],
                Response::HTTP_TOO_MANY_REQUESTS,
                ['Retry-After' => self::RATE_WINDOW],
            );
        }

        $challenge = $this->altchaService->createChallenge();

        return new JsonResponse(
            data: $challenge->toArray(),
            headers: [
                'Cache-Control' => 'no-store, no-cache, must-revalidate',
                'Pragma' => 'no-cache',
            ]
        );
    }

    /**
     * Fixed-window IP rate limiter backed by the app cache.
     * Returns true when the IP has exceeded RATE_LIMIT requests within RATE_WINDOW seconds.
     */
    private function isRateLimited(string $ip): bool
    {
        $key  = 'altcha_rl_' . hash('sha256', $ip);
        $item = $this->cache->getItem($key);

        [$count, $expiresAt] = $item->isHit() ? $item->get() : [0, time() + self::RATE_WINDOW];

        if (time() >= $expiresAt) {
            $count     = 0;
            $expiresAt = time() + self::RATE_WINDOW;
        }

        if ($count >= self::RATE_LIMIT) {
            return true;
        }

        $item->set([$count + 1, $expiresAt])
             ->expiresAt((new \DateTimeImmutable())->setTimestamp($expiresAt));
        $this->cache->save($item);

        return false;
    }
}

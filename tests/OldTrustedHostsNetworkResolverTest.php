<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use RuntimeException;
use Yiisoft\Http\Status;
use Yiisoft\Validator\Validator;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;
use Yiisoft\ProxyMiddleware\Tests\Support\MockRequestHandler;

final class OldTrustedHostsNetworkResolverTest extends TestCase
{
    protected function setUp(): void
    {
        $this->markTestIncomplete();
    }

    public function dataValidIpAndForCombination(): array
    {
        return [
            'ipv4, basic' => ['5.5.5.5'],
            // 'ipv6, basic' => ['2001:db8:3333:4444:5555:6666:7777:8888'],
            // 'ipv6, short form notation' => ['::'],
        ];
    }

    /**
     * @dataProvider dataValidIpAndForCombination
     */
    public function testValidIpAndForCombination(string $validIp): void
    {
        $middleware = $this->createTrustedHostsNetworkResolver()->withAttributeIps('resolvedIps');
        $headers = [
            'forwarded' => [
                'for=9.9.9.9',
                'for=invalid9.9.9.9',
                "for=$validIp",
                'for=2.2.2.2',
            ],
        ];
        $request = $this->createRequestWithSchemaAndHeaders(
            headers: $headers,
            serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
        );
        $requestHandler = new MockRequestHandler();
        $middleware = $middleware->withAddedTrustedHosts(
            hosts: ['18.18.18.18', '9.9.9.9', $validIp, '2.2.2.2'],
            ipHeaders: ['forwarded'],
            trustedHeaders: ['forwarded'],
        );
        $response = $middleware->process($request, $requestHandler);

        $this->assertSame(Status::OK, $response->getStatusCode());
        $this->assertSame(
            $validIp,
            $requestHandler->processedRequest->getAttribute(TrustedHostsNetworkResolver::REQUEST_CLIENT_IP),
        );
    }

    public function dataInvalidIpAndForCombination(): array
    {
        return [
            'with subnet' => ['for=5.5.5.5/11'],
            'with negation' => ['for=!5.5.5.5/32'],
            'wrong parameter name' => ['test=5.5.5.5'],
            'missing parameter name' => ['5.5.5.5'],
        ];
    }

    /**
     * @dataProvider dataInvalidIpAndForCombination
     */
    public function testInvalidIpAndForCombination(string $invalidIp): void
    {
        $middleware = $this->createTrustedHostsNetworkResolver()->withAttributeIps('resolvedIps');
        $headers = [
            'forwarded' => [
                'for=5.5.5.5',
                $invalidIp,
                'for=2.2.2.2',
            ],
        ];
        $request = $this->createRequestWithSchemaAndHeaders(
            headers: $headers,
            serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
        );
        $requestHandler = new MockRequestHandler();
        $middleware = $middleware->withAddedTrustedHosts(
            hosts: ['8.8.8.8', '18.18.18.18', '2.2.2.2'],
            ipHeaders: ['forwarded'],
            trustedHeaders: ['forwarded'],
        );
        $response = $middleware->process($request, $requestHandler);

        $this->assertSame(Status::OK, $response->getStatusCode());
        $this->assertSame(
            '2.2.2.2',
            $requestHandler->processedRequest->getAttribute(TrustedHostsNetworkResolver::REQUEST_CLIENT_IP),
        );
    }
}

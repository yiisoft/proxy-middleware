<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Tests;

use HttpSoft\Message\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\Http\Status;
use Yiisoft\ProxyMiddleware\Tests\Support\MockRequestHandler;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;
use Yiisoft\Validator\Validator;

final class NewTrustedHostsNetworkResolverTest extends TestCase
{
    public function dataProcess(): array
    {
        return [
            'remote addr not set, IPs attribute set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedHosts(['8.8.8.8', '19.19.19.19'])
                    ->withIpsAttribute('resolvedIps'),
                $this->createRequest(
                    headers: ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                ),
                [
                    'requestClientIp' => null,
                    'ipsAttribute' => ['resolvedIps', null],
                ],
            ],
            'neither remote addr, nor proxies from request are in trusted hosts, IPs attribute set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedHosts(['8.8.8.8', '19.19.19.19'])
                    ->withIpsAttribute('resolvedIps'),
                $this->createRequest(
                    headers: ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => null,
                    'ipsAttribute' => ['resolvedIps', null],
                ],
            ],

            'only remote addr in trusted hosts' => [
                $this->createMiddleware()->withTrustedHosts(['8.8.8.8', '18.18.18.18']),
                $this->createRequest(
                    headers: ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '18.18.18.18',
                ],
            ],
            'remote addr and first proxy from request in trusted hosts, header is not allowed' => [
                $this
                    ->createMiddleware()
                    ->withTrustedHosts(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC]),
                $this->createRequest(
                    headers: ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '18.18.18.18',
                ],
            ],
            'remote addr and first proxy from request in trusted hosts' => [
                $this->createMiddleware()->withTrustedHosts(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                ],
            ],
            'remote addr and first 2 proxies from request in trusted hosts, IPs attribute set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedHosts(['8.8.8.8', '5.5.5.5', '2.2.2.2', '18.18.18.18'])
                    ->withIpsAttribute('resolvedIps'),
                $this->createRequest(
                    headers: ['x-forwarded-for' => ['9.9.9.9', '7.7.7.7', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '7.7.7.7',
                    'ipsAttribute' => [
                        'resolvedIps',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                            ],
                            [
                                'ip' => '5.5.5.5',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                            ],
                        ],
                    ],
                ],
            ],

            'IP related data, RFC header, priority over headers with "X" prefix, IPs attribute set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedHosts(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withIpsAttribute('resolvedIps'),
                $this->createRequest(
                    headers: [
                        'forwarded' => [
                            'for="9.9.9.9:8083";host=example3.com;proto=http',
                            'for="5.5.5.5:8082";host=example2.com;proto=https',
                            'for="2.2.2.2:8081";host=example1.com;proto=http',
                        ],
                        'x-forwarded-proto' => ['http'],
                        'x-forwarded-host' => ['example4.com'],
                        'x-forwarded-port' => ['8084'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'ipsAttribute' => [
                        'resolvedIps',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example2.com',
                    'port' => 8082,
                ],
            ],
            'IP related data, headers with "X" prefix, IPs attribute set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedHosts(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withIpsAttribute('resolvedIps'),
                $this->createRequest(
                    headers: [
                        'x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'x-forwarded-proto' => ['https'],
                        'x-forwarded-host' => ['example.com'],
                        'x-forwarded-port' => ['8080'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'ipsAttribute' => [
                        'resolvedIps',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => 'https',
                                'host' => 'example.com',
                                'port' => 8080,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'https',
                                'host' => 'example.com',
                                'port' => 8080,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example.com',
                    'port' => 8080,
                ],
            ],
        ];
    }

    /**
     * @dataProvider dataProcess
     */
    public function testProcess(
        TrustedHostsNetworkResolver $middleware,
        ServerRequestInterface $request,
        array $expectedData,
    ): void
    {
        $requestHandler = new MockRequestHandler();

        $response = $middleware->process($request, $requestHandler);
        $this->assertSame(Status::OK, $response->getStatusCode());

        $processedRequest = $requestHandler->processedRequest;

        $this->assertSame(
            $expectedData['requestClientIp'],
            $processedRequest->getAttribute(TrustedHostsNetworkResolver::ATTRIBUTE_REQUEST_CLIENT_IP),
        );

        if (isset($expectedData['ipsAttribute'])) {
            $this->assertSame(
                $expectedData['ipsAttribute'][1],
                $processedRequest->getAttribute($expectedData['ipsAttribute'][0]),
            );
        }

        $uri = $processedRequest->getUri();

        $this->assertSame($expectedData['protocol'] ?? 'http', $uri->getScheme());
        $this->assertSame($expectedData['host'] ?? '', $uri->getHost());
        $this->assertSame($expectedData['port'] ?? null, $uri->getPort());
    }

    private function createMiddleware(): TrustedHostsNetworkResolver
    {
        $validator = new Validator();

        return new TrustedHostsNetworkResolver($validator);
    }

    private function createRequest(
        array $headers = [],
        array $serverParams = [],
        string $scheme = 'http',
    ): ServerRequestInterface {
        $request = new ServerRequest($serverParams);

        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        $uri = $request->getUri()->withScheme($scheme)->withPath('/');

        return $request->withUri($uri);
    }
}

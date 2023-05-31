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

            'RFC header, only remote addr in trusted hosts' => [
                $this->createMiddleware()->withTrustedHosts(['8.8.8.8', '18.18.18.18']),
                $this->createRequest(
                    headers: ['forwarded' => ['for=9.9.9.9', 'for=5.5.5.5', 'for=2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '18.18.18.18',
                ],
            ],
            'headers with "X" prefix, only remote addr in trusted hosts' => [
                $this->createMiddleware()->withTrustedHosts(['8.8.8.8', '18.18.18.18']),
                $this->createRequest(
                    headers: ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '18.18.18.18',
                ],
            ],
            'RFC header, remote addr and first proxy from request in trusted hosts, header is not allowed' => [
                $this
                    ->createMiddleware()
                    ->withTrustedHosts(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX]),
                $this->createRequest(
                    headers: ['forwarded' => ['for=9.9.9.9', 'for=5.5.5.5', 'for=2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '18.18.18.18',
                ],
            ],
            'headers with "X" prefix, remote addr and first proxy from request in trusted hosts, header is not allowed' => [
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
            'RFC header, remote addr and first proxy from request in trusted hosts' => [
                $this->createMiddleware()->withTrustedHosts(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: ['forwarded' => ['for=9.9.9.9', 'for=5.5.5.5', 'for=2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                ],
            ],
            'headers with "X" prefix, remote addr and first proxy from request in trusted hosts' => [
                $this->createMiddleware()->withTrustedHosts(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                ],
            ],
            'RFC header, remote addr and first 2 proxies from request in trusted hosts, IPs attribute set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedHosts(['8.8.8.8', '5.5.5.5', '2.2.2.2', '18.18.18.18'])
                    ->withIpsAttribute('resolvedIps'),
                $this->createRequest(
                    headers: ['forwarded' => ['for=9.9.9.9', 'for=7.7.7.7', 'for=5.5.5.5', 'for=2.2.2.2']],
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
            'headers with "X" prefix, remote addr and first 2 proxies from request in trusted hosts, IPs attribute set' => [
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

            'RFC header, priority over headers with "X" prefix, IP related data, IPs attribute set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedHosts(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withIpsAttribute('resolvedIps'),
                $this->createRequest(
                    headers: [
                        'forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                        'x-forwarded-for' => ['9.9.9.9', '8.8.8.8', '2.2.2.2'],
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
            'headers with "X" prefix, RFC header not in request, IP related data, IPs attribute set' => [
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
            'custom headers, highest priority, IP related data, IPs attribute set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedHosts(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([
                        [
                            'ip' => 'y-forwarded-for',
                            'protocol' => 'y-forwarded-proto',
                            'host' => 'y-forwarded-host',
                            'port' => 'y-forwarded-port',
                        ],
                        TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,
                        TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                    ])
                    ->withIpsAttribute('resolvedIps'),
                $this->createRequest(
                    headers: [
                        'forwarded' => [
                            'for=9.9.9.9:8013;proto=http;host=example13.com',
                            'for=8.8.8.8:8012;proto=http;host=example12.com',
                            'for=2.2.2.2:8011;proto=http;host=example11.com',
                        ],
                        'x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '1.1.1.1'],
                        'x-forwarded-proto' => ['http'],
                        'x-forwarded-host' => ['example2.com'],
                        'x-forwarded-port' => ['8020'],
                        'y-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'y-forwarded-proto' => ['https'],
                        'y-forwarded-host' => ['example3.com'],
                        'y-forwarded-port' => ['8030'],
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
                                'host' => 'example3.com',
                                'port' => 8030,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'https',
                                'host' => 'example3.com',
                                'port' => 8030,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example3.com',
                    'port' => 8030,
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

<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Tests;

use HttpSoft\Message\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\Http\Status;
use Yiisoft\ProxyMiddleware\Exception\InvalidConnectionChainItemException;
use Yiisoft\ProxyMiddleware\Tests\Support\MockRequestHandler;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;
use Yiisoft\Validator\Validator;

final class NewTrustedHostsNetworkResolverTest extends TestCase
{
    public function dataProcess(): array
    {
        return [
            'remote addr not set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '19.19.19.19'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                ),
                [
                    'requestClientIp' => null,
                    'connectionChainItemsAttribute' => ['connectionChainItems', null],
                ],
            ],
            'neither remote addr, nor proxies from request are in trusted IPs' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '19.19.19.19'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => null,
                    'connectionChainItemsAttribute' => ['connectionChainItems', null],
                ],
            ],

            'RFC header, in request, remote addr in trusted IPs' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['Forwarded' => ['for=9.9.9.9', 'for=5.5.5.5', 'for=2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '18.18.18.18',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                ],
            ],
            'headers with "X" prefix, in request, remote addr in trusted IPs' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '18.18.18.18',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                ],
            ],
            'forwarded headers are not in request, remote addr in trusted IPs' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '18.18.18.18',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                ],
            ],
            'RFC header, remote addr and first proxy from request in trusted IPs, header is not allowed' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['Forwarded' => ['for=9.9.9.9', 'for=5.5.5.5', 'for=2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '18.18.18.18',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                ],
            ],
            'headers with "X" prefix, remote addr and first proxy from request in trusted IPs, header is not allowed' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '18.18.18.18',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                ],
            ],
            'RFC header, remote addr and first proxy from request in trusted IPs' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['Forwarded' => ['for=9.9.9.9', 'for=5.5.5.5', 'for=2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                ],
            ],
            'headers with "X" prefix, remote addr and first proxy from request in trusted IPs' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                ],
            ],
            'RFC header, remote addr and first 2 proxies from request in trusted IPs' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '5.5.5.5', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['Forwarded' => ['for=9.9.9.9', 'for=7.7.7.7', 'for=5.5.5.5', 'for=2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '7.7.7.7',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '5.5.5.5',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                ],
            ],
            'headers with "X" prefix, remote addr and first 2 proxies from request in trusted IPs' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '5.5.5.5', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-forwarded-for' => ['9.9.9.9', '7.7.7.7', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '7.7.7.7',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '5.5.5.5',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                ],
            ],

            'RFC header, priority over headers with "X" prefix, IP related data' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                        'X-Forwarded-For' => ['9.9.9.9', '8.8.8.8', '2.2.2.2'],
                        'X-Forwarded-Proto' => ['http'],
                        'X-Forwarded-Host' => ['example4.com'],
                        'X-Forwarded-Port' => ['8084'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example2.com',
                    'port' => 8082,
                ],
            ],
            'headers with "X" prefix, RFC header not in request, IP related data' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'X-Forwarded-Proto' => ['https'],
                        'X-Forwarded-Host' => ['example.com'],
                        'X-Forwarded-Port' => ['8080'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => 'https',
                                'host' => 'example.com',
                                'port' => 8080,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'https',
                                'host' => 'example.com',
                                'port' => 8080,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example.com',
                    'port' => 8080,
                ],
            ],
            'custom headers, highest priority, IP related data' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
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
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for=9.9.9.9:8013;proto=http;host=example13.com',
                            'for=8.8.8.8:8012;proto=http;host=example12.com',
                            'for=2.2.2.2:8011;proto=http;host=example11.com',
                        ],
                        'X-forwarded-For' => ['9.9.9.9', '5.5.5.5', '1.1.1.1'],
                        'X-forwarded-Proto' => ['http'],
                        'X-forwarded-Host' => ['example2.com'],
                        'X-forwarded-Port' => ['8020'],
                        'Y-forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'Y-forwarded-Proto' => ['https'],
                        'Y-forwarded-Host' => ['example3.com'],
                        'Y-forwarded-Port' => ['8030'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => 'https',
                                'host' => 'example3.com',
                                'port' => 8030,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'https',
                                'host' => 'example3.com',
                                'port' => 8030,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example3.com',
                    'port' => 8030,
                ],
            ],
            'custom headers, IP related data, protocol mapping' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([
                        [
                            'ip' => 'y-forwarded-for',
                            'protocol' => ['front-end-https', ['On' => 'https']],
                            'host' => 'y-forwarded-host',
                            'port' => 'y-forwarded-port',
                        ],
                    ])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Y-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'Front-End-Https' => ['On'],
                        'Y-Forwarded-Host' => ['example.com'],
                        'Y-Forwarded-Port' => ['8080'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => 'https',
                                'host' => 'example.com',
                                'port' => 8080,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'https',
                                'host' => 'example.com',
                                'port' => 8080,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example.com',
                    'port' => 8080,
                ],
            ],
            'RFC header, IP related data, min allowed port' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:1";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example2.com',
                    'port' => 1,
                ],
            ],
            'RFC header, IP related data, max allowed port' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:65535";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                                'hiddenIp' => null,
                                'hiddenPort' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example2.com',
                    'port' => 65535,
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
        $this->assertSame(
            $expectedData['connectionChainItemsAttribute'][1],
            $processedRequest->getAttribute($expectedData['connectionChainItemsAttribute'][0]),
        );

        $uri = $processedRequest->getUri();

        $this->assertSame($expectedData['protocol'] ?? 'http', $uri->getScheme());
        $this->assertSame($expectedData['host'] ?? '', $uri->getHost());
        $this->assertSame($expectedData['port'] ?? null, $uri->getPort());
    }

    public function dataInvalidConnectionChainItem(): array
    {
        return [
            'IP' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', 'invalid5.5.5.5', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"invalid5.5.5.5" is not a valid IP.',
            ],
            'port, contains non-digits' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:a8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"a8081" is not a valid port.',
            ],
            'port, greater than max by 1' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:65536";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"65536" is not a valid port.',
            ],
            'port, greater than max' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:123456";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"123456" is not a valid port.',
            ],
            'port, less than min by 1' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:0";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"0" is not a valid port.',
            ],
        ];
    }

    /**
     * @dataProvider dataInvalidConnectionChainItem
     */
    public function testInvalidConnectionChainItem(
        TrustedHostsNetworkResolver $middleware,
        ServerRequestInterface $request,
        string $expectedExceptionMessage,
    ): void
    {
        $requestHandler = new MockRequestHandler();

        $this->expectException(InvalidConnectionChainItemException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $middleware->process($request, $requestHandler);
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

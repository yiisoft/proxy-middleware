<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Tests\TrustedHostsNetworkResolver;

use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\Http\Status;
use Yiisoft\ProxyMiddleware\Tests\Support\MockRequestHandler;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

final class ConfigurationTest extends TestCase
{
    public function testImmutability(): void
    {
        $middleware = $this->createMiddleware();

        $this->assertNotSame($middleware, $middleware->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']));
        $this->assertNotSame(
            $middleware,
            $middleware->withForwardedHeaderGroups([TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC]),
        );
        $this->assertNotSame(
            $middleware,
            $middleware->withTypicalForwardedHeaders([TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC]),
        );
        $this->assertNotSame($middleware, $middleware->withConnectionChainItemsAttribute('connectionChainItems'));
    }

    public function dataWithTypicalForwardedHeaders(): iterable
    {
        return [
            yield 'default' => [
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
                    ]),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8013";proto=http;host=example13.com',
                            'for="8.8.8.8:8012";proto=http;host=example12.com',
                            'for="2.2.2.2:8011";proto=http;host=example11.com',
                        ],
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '1.1.1.1'],
                        'X-Forwarded-Proto' => ['http'],
                        'X-Forwarded-Host' => ['example2.com'],
                        'X-Forwarded-Port' => ['8020'],
                        'Y-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'Y-Forwarded-Proto' => ['https'],
                        'Y-Forwarded-Host' => ['example3.com'],
                        'Y-Forwarded-Port' => ['8030'],
                        'Front-End-Https' => 'On',
                        'Non-Forwarded' => 'test',
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'removedHeaders' => [
                        'Forwarded',
                        'X-Forwarded-For',
                        'X-Forwarded-Proto',
                        'X-Forwarded-Host',
                        'X-Forwarded-Port',
                        'Front-End-Https',
                    ],
                    'remainedHeaders' => [
                        'Y-Forwarded-For',
                        'Y-Forwarded-Proto',
                        'Y-Forwarded-Host',
                        'Y-Forwarded-Port',
                        'Non-Forwarded',
                    ],
                ],
            ],
            yield 'custom, string keys are ignored' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([
                        [
                            'ip' => 'x-forwarded-for',
                            'protocol' => 'x-forwarded-proto',
                            'host' => 'x-forwarded-host',
                            'port' => 'x-forwarded-port',
                        ],
                        TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,
                    ])
                    ->withTypicalForwardedHeaders([
                        'key1' => TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                        'key2' => 'x-forwarded-for',
                        'key3' => 'x-forwarded-proto',
                        'key4' => 'x-forwarded-host',
                        'key5' => 'x-forwarded-port',
                        'key6' => 'front-end-https',
                    ]),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8013";proto=http;host=example13.com',
                            'for="8.8.8.8:8012";proto=http;host=example12.com',
                            'for="2.2.2.2:8011";proto=http;host=example11.com',
                        ],
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '1.1.1.1'],
                        'X-Forwarded-Proto' => ['http'],
                        'X-Forwarded-Host' => ['example2.com'],
                        'X-Forwarded-Port' => ['8020'],
                        'Y-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'Y-Forwarded-Proto' => ['https'],
                        'Y-Forwarded-Host' => ['example3.com'],
                        'Y-Forwarded-Port' => ['8030'],
                        'Front-End-Https' => 'On',
                        'Non-Forwarded' => 'test',
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '1.1.1.1',
                    'removedHeaders' => [
                        'Forwarded',
                        'Front-End-Https',
                    ],
                    'remainedHeaders' => [
                        'X-Forwarded-For',
                        'X-Forwarded-Proto',
                        'X-Forwarded-Host',
                        'X-Forwarded-Port',
                        'Y-Forwarded-For',
                        'Y-Forwarded-Proto',
                        'Y-Forwarded-Host',
                        'Y-Forwarded-Port',
                        'Non-Forwarded',
                    ],
                ],
            ],
            yield 'custom, case-insensitive' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([
                        [
                            'ip' => 'X-FORWARDED-FOR',
                            'protocol' => 'X-FORWARDED-PROTO',
                            'host' => 'X-FORWARDED-HOST',
                            'port' => 'X-FORWARDED-PORT',
                        ],
                        TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,
                    ])
                    ->withTypicalForwardedHeaders([
                        strtoupper(TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC),
                        'X-Forwarded-For',
                        'X-Forwarded-Proto',
                        'X-Forwarded-Host',
                        'X-Forwarded-Port',
                        'Front-End-Https',
                    ]),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8013";proto=http;host=example13.com',
                            'for="8.8.8.8:8012";proto=http;host=example12.com',
                            'for="2.2.2.2:8011";proto=http;host=example11.com',
                        ],
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '1.1.1.1'],
                        'X-Forwarded-Proto' => ['http'],
                        'X-Forwarded-Host' => ['example2.com'],
                        'X-Forwarded-Port' => ['8020'],
                        'Y-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'Y-Forwarded-Proto' => ['https'],
                        'Y-Forwarded-Host' => ['example3.com'],
                        'Y-Forwarded-Port' => ['8030'],
                        'Front-End-Https' => 'On',
                        'Non-Forwarded' => 'test',
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '1.1.1.1',
                    'removedHeaders' => [
                        'Forwarded',
                        'Front-End-Https',
                    ],
                    'remainedHeaders' => [
                        'X-Forwarded-For',
                        'X-Forwarded-Proto',
                        'X-Forwarded-Host',
                        'X-Forwarded-Port',
                        'Y-Forwarded-For',
                        'Y-Forwarded-Proto',
                        'Y-Forwarded-Host',
                        'Y-Forwarded-Port',
                        'Non-Forwarded',
                    ],
                ],
            ],
            yield 'custom, case-insensitive, protocol array' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([
                        [
                            'ip' => 'Y-FORWARDED-FOR',
                            'protocol' => [
                                'FRONT-END-HTTPS',
                                ['On' => 'https'],
                            ],
                            'host' => 'Y-FORWARDED-HOST',
                            'port' => 'Y-FORWARDED-PORT',
                        ],
                        TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,
                    ])
                    ->withTypicalForwardedHeaders([
                        strtoupper(TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC),
                        'Y-Forwarded-For',
                        'Y-Forwarded-Proto',
                        'Y-Forwarded-Host',
                        'Y-Forwarded-Port',
                        'Front-End-Https',
                    ]),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8013";proto=http;host=example13.com',
                            'for="8.8.8.8:8012";proto=http;host=example12.com',
                            'for="2.2.2.2:8011";proto=http;host=example11.com',
                        ],
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '1.1.1.1'],
                        'X-Forwarded-Proto' => ['http'],
                        'X-Forwarded-Host' => ['example2.com'],
                        'X-Forwarded-Port' => ['8020'],
                        'Y-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'Y-Forwarded-Proto' => ['https'],
                        'Y-Forwarded-Host' => ['example3.com'],
                        'Y-Forwarded-Port' => ['8030'],
                        'Front-End-Https' => 'On',
                        'Non-Forwarded' => 'test',
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '5.5.5.5',
                    'removedHeaders' => [
                        'Forwarded',
                        'Y-Forwarded-Proto',
                    ],
                    'remainedHeaders' => [
                        'X-Forwarded-For',
                        'X-Forwarded-Proto',
                        'X-Forwarded-Host',
                        'X-Forwarded-Port',
                        'Y-Forwarded-For',
                        'Y-Forwarded-Host',
                        'Y-Forwarded-Port',
                        'Front-End-Https',
                        'Non-Forwarded',
                    ],
                ],
            ],
        ];
    }

    /**
     * @dataProvider dataWithTypicalForwardedHeaders
     */
    public function testWithTypicalForwardedHeaders(
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

        foreach ($expectedData['removedHeaders'] as $header) {
            $this->assertEmpty($processedRequest->getHeader($header));
        }

        foreach ($expectedData['remainedHeaders'] as $header) {
            $this->assertNotEmpty($processedRequest->getHeader($header));
        }
    }
}

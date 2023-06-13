<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Tests;

use HttpSoft\Message\ServerRequest;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use Yiisoft\Http\Status;
use Yiisoft\ProxyMiddleware\Exception\InvalidConnectionChainItemException;
use Yiisoft\ProxyMiddleware\Exception\RfcProxyParseException;
use Yiisoft\ProxyMiddleware\Tests\Support\MockRequestHandler;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;
use Yiisoft\Validator\Validator;

final class TrustedHostsNetworkResolverTest extends TestCase
{
    public function dataWithTrustedIpsException(): array
    {
        return [
            'empty' => [
                [],
                'Trusted IPs can\'t be empty.',
            ],
            'contains invalid IP' => [
                ['8.8.8.8', 'invalid2.2.2.2', '18.18.18.18'],
                '"invalid2.2.2.2" is not a valid IP.',
            ],
        ];
    }

    /**
     * @dataProvider dataWithTrustedIpsException
     */
    public function testWithTrustedIpsException(array $trustedIps, string $expectedExceptionMessage): void
    {
        $middleware = $this->createMiddleware();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $middleware->withTrustedIps($trustedIps);
    }

    public function dataWithForwardedHeaderGroupsException(): array
    {
        return [
            'groups: empty array' => [
                [],
                'Forwarded header groups can\'t be empty.',
            ],
            'group: neither a string nor an array' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    1,
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Forwarded header group must be either an associative array or ' .
                'TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC constant.',
            ],
            'group: string, non-allowed' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    'test',
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Forwarded header group must be either an associative array or ' .
                'TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC constant.',
            ],
            'group: array, empty' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Forwarded header group array can\'t be empty.',
            ],
            'group: array, wrong keys' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => 'y-forwarded-proto',
                        'host1' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Invalid array keys for forwarded header group. The allowed and required keys are: "ip", "protocol", ' .
                '"host", "port".',
            ],
            'group: array, incomplete keys' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => 'y-forwarded-proto',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Invalid array keys for forwarded header group. The allowed and required keys are: "ip", "protocol", ' .
                '"host", "port".',
            ],
            'group: array, value is not a string' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => 'y-forwarded-proto',
                        'host' => [],
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Header name for "host" must be non-empty string.',
            ],
            'group: array, value is empty string' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => 'y-forwarded-proto',
                        'host' => '',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Header name for "host" must be non-empty string.',
            ],
            'protocol: value is neither a string nor an array' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => 1,
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Protocol header config must be either a string or an array.',
            ],
            'protocol: string, empty' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => '',
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Header name for "protocol" can\'t be empty.',
            ],
            'protocol: array, empty' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => [],
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Protocol header config array can\'t be empty.',
            ],
            'protocol: array, wrong keys' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => [
                            'test' => 'y-forwarded-proto',
                            2 => [],
                        ],
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Invalid array keys for protocol header config. The allowed and required keys are: "0", "1".',
            ],
            'protocol: array, incomplete keys' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => [
                            'y-forwarded-proto',
                        ],
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Invalid array keys for protocol header config. The allowed and required keys are: "0", "1".',
            ],
            'protocol: array, header name: not a string' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => [
                            1,
                            ['on' => 'https'],
                        ],
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Header name for "protocol" must be non-empty string.',
            ],
            'protocol: array, header name: empty string' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => [
                            '',
                            ['on' => 'https'],
                        ],
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Header name for "protocol" must be non-empty string.',
            ],
            'protocol, array, resolving: neither an array nor a callable' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => [
                            'y-forwarded-proto',
                            'test',
                        ],
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Protocol header resolving must be specified either via an associative array or a callable.',
            ],
            'protocol, array, resolving: array, empty' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => [
                            'y-forwarded-proto',
                            [],
                        ],
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Values in mapping for protocol header can\'t be empty.',
            ],
            'protocol, array, resolving: array, key is a not a string' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => [
                            'y-forwarded-proto',
                            [
                                'on1' => 'https',
                                2 => 'https',
                                'on3' => 'https'
                            ],
                        ],
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Key in mapping for protocol header must be non-empty string.',
            ],
            'protocol, array, resolving: array, key is an empty string' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => [
                            'y-forwarded-proto',
                            [
                                'on1' => 'https',
                                '' => 'https',
                                'on3' => 'https'
                            ],
                        ],
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Key in mapping for protocol header must be non-empty string.',
            ],
            'protocol, array, resolving: array, value is not allowed protocol' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => [
                            'y-forwarded-proto',
                            [
                                'on1' => 'https',
                                'on2' => 'https2',
                                'on3' => 'https'
                            ],
                        ],
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Value in mapping for protocol header must be a valid protocol. Allowed values are: "http", "https" ' .
                '(case-sensitive).',
            ],
        ];
    }

    /**
     * @dataProvider dataWithForwardedHeaderGroupsException
     */
    public function testWithForwardedHeaderGroupsException(
        array $forwardedHeaderGroups,
        string $expectedExceptionMessage,
    ): void
    {
        $middleware = $this->createMiddleware();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $middleware->withForwardedHeaderGroups($forwardedHeaderGroups);
    }

    public function dataWithTypicalForwardedHeadersException(): array
    {
        return [
            'empty' => [
                [],
                'Typical forwarded headers can\'t be empty.',
            ],
            'contains invalid header, not a string' => [
                [
                    'forwarded',
                    1,
                    'front-end-https',
                ],
                'Typical forwarded header must be non-empty string.',
            ],
            'contains invalid header, empty string' => [
                [
                    'forwarded',
                    '',
                    'front-end-https',
                ],
                'Typical forwarded header must be non-empty string.',
            ],
        ];
    }

    /**
     * @dataProvider dataWithTypicalForwardedHeadersException
     */
    public function testWithTypicalForwardedHeadersException(
        array $typicalForwardedHeaders,
        string $expectedExceptionMessage,
    ): void
    {
        $middleware = $this->createMiddleware();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $middleware->withTypicalForwardedHeaders($typicalForwardedHeaders);
    }

    public function testWithConnectionChainItemsAttributeException(): void
    {
        $middleware = $this->createMiddleware();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Attribute can\'t be empty string');
        $middleware->withConnectionChainItemsAttribute('');
    }

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

    public function dataWithTypicalForwardedHeaders(): array
    {
        return [
            'default' => [
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
                        'X-Forwarded-For',
                        'X-Forwarded-Proto',
                        'X-Forwarded-Host',
                        'X-Forwarded-Port',
                        'Front-End-Https',
                    ],
                    'remainedHeaders' => [
                        'Forwarded',
                        'Y-Forwarded-For',
                        'Y-Forwarded-Proto',
                        'Y-Forwarded-Host',
                        'Y-Forwarded-Port',
                        'Non-Forwarded',
                    ],
                ],
            ],
            'custom, string keys are ignored' => [
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
                        'key1' => strtoupper(TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC),
                        'key2' => 'X-Forwarded-For',
                        'key3' => 'X-Forwarded-Proto',
                        'key4' => 'X-Forwarded-Host',
                        'key5' => 'X-Forwarded-Port',
                        'key6' => 'Front-End-Https',
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
                    'requestClientIp' => '18.18.18.18',
                    'removedHeaders' => [
                        'Front-End-Https',
                    ],
                    'remainedHeaders' => [
                        'Forwarded',
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
            'custom, case-insensitive' => [
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
                    'requestClientIp' => '18.18.18.18',
                    'removedHeaders' => [
                        'Front-End-Https',
                    ],
                    'remainedHeaders' => [
                        'Forwarded',
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
            'custom, case-insensitive, protocol array' => [
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
                        'Y-Forwarded-Proto',
                    ],
                    'remainedHeaders' => [
                        'Forwarded',
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

    public function dataProcess(): array
    {
        return [
            'neither remote addr, nor forwarded headers are set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '19.19.19.19'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(),
                [
                    'requestClientIp' => null,
                    'connectionChainItemsAttribute' => ['connectionChainItems', null],
                ],
            ],
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
            'remote addr is empty' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '19.19.19.19'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                    serverParams: ['REMOTE_ADDR' => ''],
                ),
                [
                    'requestClientIp' => null,
                    'connectionChainItemsAttribute' => ['connectionChainItems', null],
                ],
            ],
            'forwarded headers not set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '19.19.19.19'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => null,
                    'connectionChainItemsAttribute' => ['connectionChainItems', null],
                ],
            ],
            'forwarded headers are empty' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '19.19.19.19'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-Forwarded-For' => ''],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
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
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '5.5.5.5',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
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
                    headers: ['X-Forwarded-For' => ['9.9.9.9', '7.7.7.7', '5.5.5.5', '2.2.2.2']],
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '5.5.5.5',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example2.com',
                    'port' => 8082,
                ],
            ],
            'RFC header, priority over headers with "X" prefix, IP related data, IPv6 without port' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps([
                        '2001:db8:3333:4444:5555:6666:7777:8888',
                        '2001:db8:3333:4444:5555:6666:7777:2222',
                        '2001:db8:3333:4444:5555:6666:7777:0000'
                    ])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="[2001:db8:3333:4444:5555:6666:7777:9999]";proto=http;host=example3.com',
                            'for="[2001:db8:3333:4444:5555:6666:7777:5555]";proto=https;host=example2.com',
                            'for="[2001:db8:3333:4444:5555:6666:7777:2222]";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '2001:db8:3333:4444:5555:6666:7777:0000'],
                ),
                [
                    'requestClientIp' => '2001:db8:3333:4444:5555:6666:7777:5555',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '2001:db8:3333:4444:5555:6666:7777:0000',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2001:db8:3333:4444:5555:6666:7777:2222',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => null,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example2.com',
                    'port' => null,
                ],
            ],
            'RFC header, priority over headers with "X" prefix, IP related data, IPv6 with port' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps([
                        '2001:db8:3333:4444:5555:6666:7777:8888',
                        '2001:db8:3333:4444:5555:6666:7777:2222',
                        '2001:db8:3333:4444:5555:6666:7777:0000'
                    ])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="[2001:db8:3333:4444:5555:6666:7777:9999]:8083";proto=http;host=example3.com',
                            'for="[2001:db8:3333:4444:5555:6666:7777:5555]:8082";proto=https;host=example2.com',
                            'for="[2001:db8:3333:4444:5555:6666:7777:2222]:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '2001:db8:3333:4444:5555:6666:7777:0000'],
                ),
                [
                    'requestClientIp' => '2001:db8:3333:4444:5555:6666:7777:5555',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '2001:db8:3333:4444:5555:6666:7777:0000',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2001:db8:3333:4444:5555:6666:7777:2222',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'https',
                                'host' => 'example.com',
                                'port' => 8080,
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'https',
                                'host' => 'example3.com',
                                'port' => 8030,
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'https',
                                'host' => 'example.com',
                                'port' => 8080,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example.com',
                    'port' => 8080,
                ],
            ],
            'custom headers, IP related data, protocol mapping, protocol header not set' => [
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
                                'protocol' => null,
                                'host' => 'example.com',
                                'port' => 8080,
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => null,
                                'host' => 'example.com',
                                'port' => 8080,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'http',
                    'host' => 'example.com',
                    'port' => 8080,
                ],
            ],
            'custom headers, IP related data, protocol mapping, protocol header is empty' => [
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
                        'Front-End-Https' => '',
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
                                'protocol' => null,
                                'host' => 'example.com',
                                'port' => 8080,
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => null,
                                'host' => 'example.com',
                                'port' => 8080,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'http',
                    'host' => 'example.com',
                    'port' => 8080,
                ],
            ],
            'custom headers, IP related data, protocol resolving via callable' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([
                        [
                            'ip' => 'y-forwarded-for',
                            'protocol' => [
                                'front-end-https',
                                static fn (string $protocol): ?string => $protocol === 'On' ? 'https': 'http',
                            ],
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'https',
                                'host' => 'example.com',
                                'port' => 8080,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example.com',
                    'port' => 8080,
                ],
            ],
            'RFC header, IP related data, string keys in trusted IPs and forwarded header groups are ignored' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['key3' => '8.8.8.8', 'key2' => '2.2.2.2', 'key1' => '18.18.18.18'])
                    ->withForwardedHeaderGroups([
                        'key1' => TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,
                        'key2' => TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                    ])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'FOR="5.5.5.5:8082";PROTO=HTTPS;HOST=EXAMPLE2.COM',
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example2.com',
                    'port' => 8082,
                ],
            ],
            'RFC header, IP related data, case-insensitive' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'FOR="5.5.5.5:8082";PROTO=HTTPS;HOST=EXAMPLE2.COM',
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example2.com',
                    'port' => 8082,
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                                'ipIdentifier' => null,
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example2.com',
                    'port' => 65535,
                ],
            ],
            'RFC header, IP related data, hidden IP, unknown' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="unknown";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '2.2.2.2',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                                'ipIdentifier' => null,
                            ]
                        ],
                    ],
                    'protocol' => 'http',
                    'host' => 'example1.com',
                    'port' => 8081,
                ],
            ],
            'RFC header, IP related data, hidden IP, obfuscated, no reverse-obfuscating' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="_obfuscated";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                [
                    'requestClientIp' => '2.2.2.2',
                    'connectionChainItemsAttribute' => [
                        'connectionChainItems',
                        [
                            [
                                'ip' => '18.18.18.18',
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => 8081,
                                'ipIdentifier' => null,
                            ]
                        ],
                    ],
                    'protocol' => 'http',
                    'host' => 'example1.com',
                    'port' => 8081,
                ],
            ],
            'RFC header, IP related data, hidden IP, obfuscated, reverse-obfuscating' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver
                {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array
                    {
                        return match ($ipIdentifier) {
                            '_obfuscated1' => ['2.2.2.2', null],
                            '_obfuscated2' => ['5.5.5.5', '8082'],
                            default => null,
                        };
                    }
                })
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="_obfuscated2";proto=https;host=example2.com',
                            'for="_obfuscated1";proto=http;host=example1.com',
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
                                'ipIdentifier' => null,
                            ],
                            [
                                'ip' => '2.2.2.2',
                                'protocol' => 'http',
                                'host' => 'example1.com',
                                'port' => null,
                                'ipIdentifier' => '_obfuscated1',
                            ]
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example2.com',
                    'port' => 8082,
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

    public function dataRfcProxyParseException(): array
    {
        return [
            'badly formed header value, no double quotes for IP with port' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for=5.5.5.5:8082;proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                'Unable to parse RFC header value: "for=5.5.5.5:8082;proto=https;host=example2.com".',
            ],
            'missing "for" directive' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"for" directive is required.',
            ],
            'contains non-allowed directive' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host=example2.com;test=value',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"test" is not a valid directive. Allowed values are: "by", "for", "proto", "host" (case-insensitive).',
            ],
            'invalid "for" directive' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for=":";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                'IP is missing in "for" directive.',
            ],
            'not IPv6 enclosed in square brackets' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="[5.5.5.5]:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                'Enclosing in square brackets assumes presence of valid IPv6, "5.5.5.5" given.',
            ],
        ];
    }

    /**
     * @dataProvider dataRfcProxyParseException
     */
    public function testRfcProxyParseException(
        TrustedHostsNetworkResolver $middleware,
        ServerRequestInterface $request,
        string $expectedExceptionMessage,
    ): void
    {
        $requestHandler = new MockRequestHandler();

        $this->expectException(RfcProxyParseException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $middleware->process($request, $requestHandler);
    }

    public function dataInvalidConnectionChainItemException(): array
    {
        return [
            'IP, remote addr' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => 'invalid18.18.18.18'],
                ),
                '"invalid18.18.18.18" is not a valid IP.',
            ],
            'IP, RFC header' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="invalid5.5.5.5:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"invalid5.5.5.5" is not a valid IP.',
            ],
            'IP, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', 'invalid5.5.5.5', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"invalid5.5.5.5" is not a valid IP.',
            ],
            'IP with port, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5:8082', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"5.5.5.5:8082" is not a valid IP.',
            ],
            'IP identifier, unknown, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', 'unknown', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"unknown" is not a valid IP.',
            ],
            'IP identifier, obfuscated, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '_obfuscated', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"_obfuscated" is not a valid IP.',
            ],
            'IP identifier with port, unknown, RFC header' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="unknown:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"unknown" is not a valid IP.',
            ],
            'IP identifier with port, unknown, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', 'unknown:8082', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"unknown:8082" is not a valid IP.',
            ],
            'IP identifier with port, obfuscated, RFC header' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="_obfuscated:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"_obfuscated" is not a valid IP.',
            ],
            'IP identifier with port, obfuscated, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '_obfuscated:8082', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"_obfuscated:8082" is not a valid IP.',
            ],
            'protocol, RFC header' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https1;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"https1" protocol is not allowed. Allowed values are: "http", "https" (case-sensitive).',
            ],
            'protocol, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'X-Forwarded-Proto' => ['https1'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"https1" protocol is not allowed. Allowed values are: "http", "https" (case-sensitive).',
            ],
            'host, RFC header' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host=_example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"_example2.com" is not a valid host',
            ],
            'host, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'X-Forwarded-Host' => ['_example2.com'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"_example2.com" is not a valid host',
            ],
            'port, greater than max by 1, RFC header' => [
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
                '"65536" is not a valid port. Port must be a number between 1 and 65535.',
            ],
            'port, greater than max within allowed max length, RFC header' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:99999";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"99999" is not a valid port. Port must be a number between 1 and 65535.',
            ],
            'port, greater than max, RFC header' => [
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
                '"123456" is not a valid port. Port must be a number between 1 and 65535.',
            ],
            'port, contains non-allowed characters, RFC header' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host=example2.com',
                            'for="2.2.2.2:a1234";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"a1234" is not a valid port. Port must be a number between 1 and 65535.',
            ],
            'port, less than min by 1, RFC header' => [
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
                '"0" is not a valid port. Port must be a number between 1 and 65535.',
            ],
            'port, greater than max, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'X-Forwarded-Port' => ['123456'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"123456" is not a valid port. Port must be a number between 1 and 65535.',
            ],
        ];
    }

    /**
     * @dataProvider dataInvalidConnectionChainItemException
     */
    public function testInvalidConnectionChainItemException(
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

    public function dataGetProtocolException(): array
    {
        return [
            'mapping, no matching item' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([
                        [
                            'ip' => 'y-forwarded-for',
                            'protocol' => [
                                'front-end-https',
                                ['Test' => 'https'],
                            ],
                            'host' => 'y-forwarded-host',
                            'port' => 'y-forwarded-port',
                        ],
                    ]),
                $this->createRequest(
                    headers: [
                        'Y-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'Front-End-Https' => ['On'],
                        'Y-Forwarded-Host' => ['example.com'],
                        'Y-Forwarded-Port' => ['8080'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                'Unable to resolve "On" protocol via mapping.',
            ],
            'callable, return value is null' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([
                        [
                            'ip' => 'y-forwarded-for',
                            'protocol' => [
                                'front-end-https',
                                static fn (string $protocol): ?string => null,
                            ],
                            'host' => 'y-forwarded-host',
                            'port' => 'y-forwarded-port',
                        ],
                    ]),
                $this->createRequest(
                    headers: [
                        'Y-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'Front-End-Https' => ['On'],
                        'Y-Forwarded-Host' => ['example.com'],
                        'Y-Forwarded-Port' => ['8080'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                'Unable to resolve "On" protocol via callable.',
            ],
            'callable, return value is not a valid protocol' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([
                        [
                            'ip' => 'y-forwarded-for',
                            'protocol' => [
                                'front-end-https',
                                static fn (string $protocol): ?string => 'test',
                            ],
                            'host' => 'y-forwarded-host',
                            'port' => 'y-forwarded-port',
                        ],
                    ]),
                $this->createRequest(
                    headers: [
                        'Y-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                        'Front-End-Https' => ['On'],
                        'Y-Forwarded-Host' => ['example.com'],
                        'Y-Forwarded-Port' => ['8080'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                'Value returned from callable for protocol header must be a valid protocol. Allowed values are: ' .
                '"http", "https" (case-sensitive).',
            ],
        ];
    }

    /**
     * @dataProvider dataGetProtocolException
     */
    public function testGetProtocolException(
        TrustedHostsNetworkResolver $middleware,
        ServerRequestInterface $request,
        string $expectedExceptionMessage,
    ): void
    {
        $requestHandler = new MockRequestHandler();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $middleware->process($request, $requestHandler);
    }

    public function dataReverseObfuscateIpIdentifierException(): array
    {
        return [
            'empty array' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver
                {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array
                    {
                        return [];
                    }
                })
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="_obfuscated";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                'Reverse-obfuscated IP data can\'t be empty.',
            ],
            'wrong items count' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver
                {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array
                    {
                        return ['2.2.2.2', '8081', 'test'];
                    }
                })
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="_obfuscated";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                'Invalid array keys for reverse-obfuscated IP data. The allowed and required keys are: "0", "1".',
            ],
            'IP is empty string' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver
                {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array
                    {
                        return ['', '8081'];
                    }
                })
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="_obfuscated";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                'IP returned from reverse-obfuscated IP data must be non-empty string.',
            ],
            'Port is empty string' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver
                {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array
                    {
                        return ['2.2.2.2', ''];
                    }
                })
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="_obfuscated";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                'Port returned from reverse-obfuscated IP data must be non-empty string.',
            ],
        ];
    }

    /**
     * @dataProvider dataReverseObfuscateIpIdentifierException
     */
    public function testReverseObfuscateIpIdentifierException(
        TrustedHostsNetworkResolver $middleware,
        ServerRequestInterface $request,
        string $expectedExceptionMessage
    ): void
    {
        $requestHandler = new MockRequestHandler();

        $this->expectException(RuntimeException::class);
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

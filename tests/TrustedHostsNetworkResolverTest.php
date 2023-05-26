<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Tests;

use InvalidArgumentException;
use HttpSoft\Message\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use Yiisoft\Http\Status;
use Yiisoft\Validator\Validator;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;
use Yiisoft\ProxyMiddleware\Tests\Support\MockRequestHandler;

final class TrustedHostsNetworkResolverTest extends TestCase
{
    public function dataProcessTrusted(): array
    {
        return [
            // Hosts

            'hosts: server IP' => [[
                'headers' => ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                'trustedHosts' => [
                    ['hosts' => ['127.0.0.1'], 'ipHeaders' => ['x-forwarded-for']],
                ],
                'expectedClientIp' => null,
            ]],
            'hosts: server IP, with first one proxy, ipHeaders: not set' => [[
                'headers' => ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                'trustedHosts' => [
                    ['hosts' => ['2.2.2.2', '127.0.0.1'], 'ipHeaders' => []],
                ],
                'expectedClientIp' => '127.0.0.1',
            ]],
            'hosts: server IP with first one proxy' => [[
                'headers' => ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                'trustedHosts' => [
                    ['hosts' => ['2.2.2.2', '127.0.0.1'], 'ipHeaders' => ['x-forwarded-for']],
                ],
                'expectedClientIp' => '5.5.5.5',
            ]],
            'hosts: server IP with first few proxies' => [[
                'headers' => ['x-forwarded-for' => ['9.9.9.9', '8.8.8.8', '5.5.5.5', '2.2.2.2']],
                'trustedHosts' => [
                    ['hosts' => ['5.5.5.5', '2.2.2.2', '127.0.0.1'], 'ipHeaders' => ['x-forwarded-for']],
                ],
                'expectedClientIp' => '8.8.8.8',
            ]],

            // Port headers

            'port headers, separate header value' => [[
                'headers' => ['x-forwarded-for' => ['1234']],
                'trustedHosts' => [
                    ['hosts' => ['172.16.0.1', '127.0.0.1'], 'ipHeaders' => [], 'portHeaders' => ['x-forwarded-for']],
                ],
                'expectedClientIp' => '127.0.0.1',
                'expectedHttpHost' => '',
                'expectedHttpScheme' => 'http',
                'expectedPath' => '/',
                'expectedQuery' => '',
                'expectedPort' => 1234,
            ]],
            'port headers, provided with proxy' => [[
                'headers' => [
                    'x-forwarded-for' => ['1234'],
                    'forwarded' => ['for=9.9.9.9', 'proto=http;for="5.5.5.5:4321";host=test', 'for=2.2.2.2'],
                ],
                'trustedHosts' => [
                    [
                        'hosts' => ['2.2.2.2', '127.0.0.1'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'hostHeaders' => ['forwarded'],
                        'portHeaders' => ['forwarded', 'x-forwarded-for'],
                        'trustedHeaders' => ['forwarded', 'x-forwarded-for'],
                    ],
                ],
                'expectedClientIp' => '5.5.5.5',
                'expectedHttpHost' => 'test',
                'expectedHttpScheme' => 'http',
                'expectedPath' => '/',
                'expectedQuery' => '',
                'expectedPort' => 4321,
            ]],

            'xForward, level 6' => [[
                'headers' => ['x-forwarded-proto' => ['https']],
                'trustedHosts' => [
                    [
                        'hosts' => ['172.16.0.1', '127.0.0.1'],
                        'protocolHeaders' => ['x-forwarded-proto' => ['http' => 'http', 'https' => 'https']],
                    ],
                ],
                'expectedClientIp' => '127.0.0.1',
                'expectedHttpHost' => '',
                'expectedHttpScheme' => 'https',
            ]],
            'rfc7239, level 1' => [[
                'headers' => ['forwarded' => ['for=9.9.9.9', 'for=5.5.5.5', 'for=2.2.2.2']],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'trustedHeaders' => ['forwarded'],
                    ],
                ],
                'expectedClientIp' => null,
            ]],
            'rfc7239, level 2' => [[
                'headers' => ['forwarded' => ['for=9.9.9.9', 'for=5.5.5.5', 'for=2.2.2.2']],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'trustedHeaders' => ['forwarded'],
                    ],
                ],
                'expectedClientIp' => '5.5.5.5',
            ]],
            'rfc7239, level 2, obfuscated host, unknown' => [[
                'headers' => ['forwarded' => ['for=unknown', 'to=unknown']],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                    ],
                ],
                'expectedClientIp' => '127.0.0.1',
            ]],
            'rfc7239, level 2, obfuscated host, unknown, with port' => [[
                'headers' => ['forwarded' => ['for=unknown:1']],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                    ],
                ],
                'expectedClientIp' => '127.0.0.1',
            ]],
            'rfc7239, level 3' => [[
                'headers' => ['forwarded' => ['to=9.9.9.9', 'for=5.5.5.5', 'for=2.2.2.2']],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'trustedHeaders' => ['forwarded'],
                    ],
                ],
                'expectedClientIp' => '5.5.5.5',
            ]],
            'rfc7239, level 5, host, protocol' => [[
                'headers' => ['forwarded' => ['for=9.9.9.9', 'proto=https;for=5.5.5.5;host=test', 'for=2.2.2.2']],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'hostHeaders' => ['x-forwarded-host', 'forwarded'],
                        'protocolHeaders' => [
                            'x-forwarded-proto' => ['http' => 'http'],
                            'forwarded' => ['http' => 'http', 'https' => 'https'],
                        ],
                        'trustedHeaders' => ['forwarded'],
                    ],
                ],
                'expectedClientIp' => '5.5.5.5',
                'expectedHttpHost' => 'test',
                'expectedHttpScheme' => 'https',
            ]],
            'rfc7239, level 5, host, protocol, multiple headers, uppercase' => [[
                'headers' => [
                    'forwarded' => ['for=9.9.9.9', 'proto=https;for=5.5.5.5;host=test', 'for=2.2.2.2'],
                    'forwarded-custom' => ['for=7.7.7.7', 'proto=https;for=4.4.4.4;host=test', 'for=1.1.1.1'],
                ],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'hostHeaders' => ['x-forwarded-host', 'forwarded', 'forwarded-custom'],
                        'protocolHeaders' => [
                            'x-forwarded-proto' => ['http' => 'http'],
                            'FORWARDED' => ['http' => 'http', 'https' => 'https'],
                        ],
                        'trustedHeaders' => ['forwarded', 'forwarded-custom'],
                    ],
                ],
                'expectedClientIp' => '5.5.5.5',
                'expectedHttpHost' => 'test',
                'expectedHttpScheme' => 'https',
            ]],
            'rfc7239, level 6, host, protocol, url with query parameters' => [[
                'headers' => [
                    'forwarded' => ['for=9.9.9.9', 'proto=https;for=5.5.5.5;host=test', 'for=2.2.2.2'],
                    'x-rewrite-url' => ['/test?test=test'],
                ],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'hostHeaders' => ['forwarded'],
                        'protocolHeaders' => ['forwarded' => fn () => ['http' => 'http', 'https' => 'https']],
                        'urlHeaders' => ['non-existing-header', 'x-rewrite-url'],
                        'trustedHeaders' => ['forwarded', 'x-rewrite-url'],
                    ],
                ],
                'expectedClientIp' => '5.5.5.5',
                'expectedHttpHost' => 'test',
                'expectedHttpScheme' => 'https',
                'expectedPath' => '/test',
                'expectedQuery' => 'test=test',
            ]],
            'rfc7239, level 6, host, protocol, url without query parameters' => [[
                'headers' => [
                    'forwarded' => ['for=9.9.9.9', 'proto=https;for=5.5.5.5;host=test', 'for=2.2.2.2'],
                    'x-rewrite-url' => ['/test'],
                ],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'hostHeaders' => ['forwarded'],
                        'protocolHeaders' => ['forwarded' => fn () => ['http' => 'http', 'https' => 'https']],
                        'urlHeaders' => ['non-existing-header', 'x-rewrite-url'],
                        'trustedHeaders' => ['forwarded', 'x-rewrite-url'],
                    ],
                ],
                'expectedClientIp' => '5.5.5.5',
                'expectedHttpHost' => 'test',
                'expectedHttpScheme' => 'https',
                'expectedPath' => '/test',
                'expectedQuery' => '',
            ]],
            'rfc7239, level 6, host, protocol, url with badly formed query parameters' => [[
                'headers' => [
                    'forwarded' => ['for=9.9.9.9', 'proto=https;for=5.5.5.5;host=test', 'for=2.2.2.2'],
                    'x-rewrite-url' => ['/test?param1=val1?param2=val2'],
                ],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'hostHeaders' => ['forwarded'],
                        'protocolHeaders' => ['forwarded' => fn () => ['http' => 'http', 'https' => 'https']],
                        'urlHeaders' => ['non-existing-header', 'x-rewrite-url'],
                        'trustedHeaders' => ['forwarded', 'x-rewrite-url'],
                    ],
                ],
                'expectedClientIp' => '5.5.5.5',
                'expectedHttpHost' => 'test',
                'expectedHttpScheme' => 'https',
                'expectedPath' => '/test',
                'expectedQuery' => 'param1=val1?param2=val2',
            ]],

            // Protocol headers

            'rfc7239, level 7, another host, another protocol (prioritized), url, case insensitive protocol headers' => [[
                'headers' => [
                    'forwarded' => ['for=9.9.9.9', 'proto=http;for=5.5.5.5;host=test', 'for=2.2.2.2'],
                    'x-rewrite-url' => ['/test?test=test'],
                    'x-forwarded-host' => ['test.another'],
                    'front-end-https' => ['on'],
                ],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'hostHeaders' => ['x-forwarded-host', 'forwarded'],
                        'protocolHeaders' => [
                            'front-end-https' => ['HTTPS' => 'on'],
                            'forwarded' => ['http' => 'http', 'https' => 'https'],
                        ],
                        'urlHeaders' => ['x-rewrite-url'],
                        'trustedHeaders' => ['forwarded', 'x-rewrite-url', 'x-forwarded-host', 'front-end-https'],
                    ],
                ],
                'expectedClientIp' => '5.5.5.5',
                'expectedHttpHost' => 'test.another',
                'expectedHttpScheme' => 'https',
                'expectedPath' => '/test',
                'expectedQuery' => 'test=test',
            ]],
            'rfc7239, level 8, another host, another protocol, url, ports (string, valid, missing)' => [[
                'headers' => [
                    'x-rewrite-url' => ['/test?test=test'],
                    'x-forwarded-host' => ['test.another'],
                    'front-end-https' => ['on'],
                    'forwarded' => ['for="9.9.9.9:abs"', 'proto=http;for="5.5.5.5:123";host=test', 'for=2.2.2.2'],
                ],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'hostHeaders' => ['x-forwarded-host', 'forwarded'],
                        'protocolHeaders' => [
                            'forwarded' => ['http' => 'http', 'https' => 'https'],
                            'front-end-https' => ['https' => 'on'],
                        ],
                        'urlHeaders' => ['x-rewrite-url'],
                        'portHeaders' => ['x-forwarded-port', 'forwarded'],
                        'trustedHeaders' => ['x-rewrite-url', 'x-forwarded-host', 'front-end-https', 'forwarded'],
                    ],
                ],
                'expectedClientIp' => '5.5.5.5',
                'expectedHttpHost' => 'test.another',
                'expectedHttpScheme' => 'http',
                'expectedPath' => '/test',
                'expectedQuery' => 'test=test',
                'expectedPort' => 123,
            ]],
            'rfc7239, level 8, another host, another protocol, url, ports (greater than max by 1, long, min allowed)' => [[
                'headers' => [
                    'x-rewrite-url' => ['/test?test=test'],
                    'x-forwarded-host' => ['test.another'],
                    'front-end-https' => ['on'],
                    'forwarded' => [
                        'for="9.9.9.9:65536"',
                        'proto=http;for="5.5.5.5:123456";host=test',
                        'for="2.2.2.2:1"',
                    ],
                ],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'hostHeaders' => ['x-forwarded-host', 'forwarded'],
                        'protocolHeaders' => [
                            'forwarded' => ['http' => 'http', 'https' => 'https'],
                            'front-end-https' => ['https' => 'on'],
                        ],
                        'urlHeaders' => ['x-rewrite-url'],
                        'portHeaders' => ['x-forwarded-port', 'forwarded'],
                        'trustedHeaders' => ['x-rewrite-url', 'x-forwarded-host', 'front-end-https', 'forwarded'],
                    ],
                ],
                'expectedClientIp' => '2.2.2.2',
                'expectedHttpHost' => 'test.another',
                'expectedHttpScheme' => 'https',
                'expectedPath' => '/test',
                'expectedQuery' => 'test=test',
                'expectedPort' => 1,
            ]],
            'rfc7239, level 8, another host, another protocol, url, ports (less than min by 1, long, max allowed)' => [[
                'headers' => [
                    'x-rewrite-url' => ['/test?test=test'],
                    'x-forwarded-host' => ['test.another'],
                    'front-end-https' => ['on'],
                    'forwarded' => [
                        'for="9.9.9.9:0"',
                        'proto=http;for="5.5.5.5:123456";host=test',
                        'for="2.2.2.2:65535"',
                    ],
                ],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
                        'ipHeaders' => [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
                        'hostHeaders' => ['x-forwarded-host', 'forwarded'],
                        'protocolHeaders' => [
                            'forwarded' => ['http' => 'http', 'https' => 'https'],
                            'front-end-https' => ['https' => 'on'],
                        ],
                        'urlHeaders' => ['x-rewrite-url'],
                        'portHeaders' => ['x-forwarded-port', 'forwarded'],
                        'trustedHeaders' => ['x-rewrite-url', 'x-forwarded-host', 'front-end-https', 'forwarded'],
                    ],
                ],
                'expectedClientIp' => '2.2.2.2',
                'expectedHttpHost' => 'test.another',
                'expectedHttpScheme' => 'https',
                'expectedPath' => '/test',
                'expectedQuery' => 'test=test',
                'expectedPort' => 65535,
            ]],

            // Trusted headers

            'trusted headers' => [[
                'headers' => ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'], 'foo' => 'bar'],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1'],
                        'ipHeaders' => ['x-forwarded-for'],
                        'trustedHeaders' => ['x-forwarded-for'],
                    ],
                ],
                'expectedClientIp' => null,
            ]],
            'trusted headers, custom, multiple, trust custom' => [[
                'headers' => [
                    'x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                    'custom-x-forwarded-for' => ['7.7.7.7', '4.4.4.4', '1.1.1.1'],
                    'foo' => 'bar',
                ],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1'],
                        'ipHeaders' => ['x-forwarded-for', 'custom-x-forwarded-for'],
                        'trustedHeaders' => ['custom-x-forwarded-for'],
                    ],
                ],
                'expectedClientIp' => null,
            ]],
            'trusted headers, custom, multiple, trust default' => [[
                'headers' => [
                    'custom-x-forwarded-for' => ['7.7.7.7', '4.4.4.4', '1.1.1.1'],
                    'x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                    'foo' => 'bar',
                ],
                'trustedHosts' => [
                    [
                        'hosts' => ['8.8.8.8', '127.0.0.1'],
                        'ipHeaders' => ['x-forwarded-for', 'custom-x-forwarded-for'],
                    ],
                ],
                'expectedClientIp' => null,
            ]],
        ];
    }

    /**
     * @dataProvider dataProcessTrusted
     */
    public function testProcessTrusted(array $data): void
    {
        $headers = $data['headers'];
        $trustedHosts = $data['trustedHosts'];
        $expectedClientIp = $data['expectedClientIp'];
        $expectedHttpHost = $data['expectedHttpHost'] ?? null;
        $expectedHttpScheme = $data['expectedHttpScheme'] ?? 'http';
        $expectedPath = $data['expectedPath'] ?? '/';
        $expectedQuery = $data['expectedQuery'] ?? '';
        $expectedPort = $data['expectedPort'] ?? null;

        $request = $this->createRequestWithSchemaAndHeaders(
            headers: $headers,
            serverParams: ['REMOTE_ADDR' => '127.0.0.1'],
        );
        $requestHandler = new MockRequestHandler();
        $middleware = in_array('for=unknown', $headers['forwarded'] ?? [], true) ?
            $this->createCustomTrustedHostsNetworkResolver() :
            $this->createTrustedHostsNetworkResolver();

        foreach ($trustedHosts as $data) {
            $middleware = $middleware->withAddedTrustedHosts(...$data);
        }

        $response = $middleware->process($request, $requestHandler);

        if ($expectedHttpHost !== null) {
            $this->assertSame($expectedHttpHost, $requestHandler->processedRequest->getUri()->getHost());
        }

        $this->assertSame(Status::OK, $response->getStatusCode());
        $this->assertSame(
            $expectedClientIp,
            $requestHandler->processedRequest->getAttribute(TrustedHostsNetworkResolver::REQUEST_CLIENT_IP),
        );
        $this->assertSame($expectedHttpScheme, $requestHandler->processedRequest->getUri()->getScheme());
        $this->assertSame($expectedPath, $requestHandler->processedRequest->getUri()->getPath());
        $this->assertSame($expectedQuery, $requestHandler->processedRequest->getUri()->getQuery());
        $this->assertSame($expectedPort, $requestHandler->processedRequest->getUri()->getPort());
    }

    public function dataProcessNotTrusted(): array
    {
        return [
            'none' => [
                [],
                [],
            ],
            'x-forwarded-for' => [
                ['x-forwarded-for' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                ['hosts' => ['8.8.8.8'], 'ipHeaders' => ['x-forwarded-for']],
            ],
            'rfc7239' => [
                ['x-forwarded-for' => ['for=9.9.9.9', 'for=5.5.5.5', 'for=2.2.2.2']],
                ['hosts' => ['8.8.8.8'], 'ipHeaders' => ['x-forwarded-for']],
            ],
        ];
    }

    /**
     * @dataProvider dataProcessNotTrusted
     */
    public function testProcessNotTrusted(array $headers, array $trustedHostsData): void
    {
        $middleware = $this->createTrustedHostsNetworkResolver();

        if ($trustedHostsData !== []) {
            $middleware = $middleware->withAddedTrustedHosts(...$trustedHostsData);
        }

        $request = $this->createRequestWithSchemaAndHeaders(
            headers: $headers,
            serverParams: ['REMOTE_ADDR' => '127.0.0.1'],
        );
        $requestHandler = new MockRequestHandler();

        $middleware->process($request, $requestHandler);
        $this->assertNull(
            $requestHandler->processedRequest->getAttribute(TrustedHostsNetworkResolver::REQUEST_CLIENT_IP)
        );
    }

    public function dataWithAddedTrustedHostsAndWrongArguments(): array
    {
        $hostWithWrongStructure = str_repeat('1', 68);
        $data = [
            // hosts

            [
                ['hosts' => []],
                'Empty hosts are not allowed.',
            ],
            [
                ['hosts' => ['1.1.1.1', $hostWithWrongStructure, '2.2.2.2']],
                "\"$hostWithWrongStructure\" host must be either a domain or an IP address.",
            ],

            // ipHeaders

            [
                [
                    'ipHeaders' => [
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header1'],
                        'x-forwarded-for',
                        1,
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header2'],
                    ],
                ],
                'IP header must have either string or array type.',
            ],
            [
                [
                    'ipHeaders' => [
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header1'],
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239],
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header2'],
                    ],
                ],
                'IP header array must have exactly 2 elements.',
            ],
            [
                [
                    'ipHeaders' => [
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header1'],
                        ['a', 'b', 'c'],
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header2'],
                    ],
                ],
                'IP header array must have exactly 2 elements.',
            ],
            [
                [
                    'ipHeaders' => [
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header1'],
                        [1, 'b'],
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header2'],
                    ],
                ],
                'IP header type must be a string.',
            ],
            [
                [
                    'ipHeaders' => [
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header1'],
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 1],
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header2'],
                    ],
                ],
                'IP header value must be a string.',
            ],
            [
                [
                    'ipHeaders' => [
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header1'],
                        ['a', 'header2'],
                        [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'header3'],
                    ],
                ],
                'Not supported IP header type: "a".',
            ],

            // protocolHeaders

            [
                [
                    'protocolHeaders' => [
                        'x-forwarded-proto' => ['http' => 'http'],
                        'header',
                        'forwarded' => ['http' => 'http', 'https' => 'https'],
                    ],
                ],
                'The protocol header array key must be a string.',
            ],
            [
                [
                    'protocolHeaders' => [
                        'x-forwarded-proto' => ['http' => 'http'],
                        'header' => [],
                        'forwarded' => ['http' => 'http', 'https' => 'https'],
                    ],
                ],
                'Accepted values for protocol headers cannot be an empty array.',
            ],
            [
                [
                    'protocolHeaders' => [
                        'x-forwarded-proto' => ['http' => 'http'],
                        'header' => 1,
                        'forwarded' => ['http' => 'http', 'https' => 'https'],
                    ],
                ],
                'Accepted values for protocol headers must be either an array or a callable returning array.',
            ],
            [
                [
                    'protocolHeaders' => [
                        'x-forwarded-proto' => ['http' => 'http'],
                        'header' => 1,
                        'forwarded' => fn () => 'http',
                    ],
                ],
                'Accepted values for protocol headers must be either an array or a callable returning array.',
            ],
            [
                [
                    'protocolHeaders' => [
                        'x-forwarded-proto' => ['http' => 'http'],
                        'header' => ['http' => 'http', 1 => 'http', 'https' => 'https'],
                        'forwarded' => ['http' => 'http', 'https' => 'https'],
                    ],
                ],
                'The protocol must be a string.',
            ],
            [
                [
                    'protocolHeaders' => [
                        'x-forwarded-proto' => ['http' => 'http'],
                        'header' => ['http' => 'http', '' => 'http', 'https' => 'https'],
                        'forwarded' => ['http' => 'http', 'https' => 'https'],
                    ],
                ],
                'The protocol must be non-empty string.',
            ],
        ];
        foreach (['hosts', 'hostHeaders', 'urlHeaders', 'portHeaders', 'trustedHeaders'] as $argumentName) {
            $data[] = [
                [$argumentName => ['a', 2, 'c']],
                "Each \"$argumentName\" item must be string.",
            ];
            $data[] = [
                [$argumentName => ['a', '', 'c']],
                "Each \"$argumentName\" item must be non-empty string.",
            ];
            $data[] = [
                [$argumentName => ['a', ' ', 'c']],
                "Each \"$argumentName\" item must be non-empty string.",
            ];
        }

        return $data;
    }

    /**
     * @dataProvider dataWithAddedTrustedHostsAndWrongArguments
     */
    public function testWithAddedTrustedHostsAndWrongArguments(
        array $arguments,
        string $expectedExceptionMessage,
    ): void {
        $arguments['hosts'] ??= ['9.9.9.9', '5.5.5.5', '2.2.2.2'];
        $middleware = $this->createTrustedHostsNetworkResolver();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);

        $middleware->withAddedTrustedHosts(...$arguments);
    }

    public function testProcessWithAttributeIpsAndWithoutActualHost(): void
    {
        $request = $this->createRequestWithSchemaAndHeaders();
        $requestHandler = new MockRequestHandler();
        $response = $this
            ->createTrustedHostsNetworkResolver()
            ->withAttributeIps('ip')
            ->process($request, $requestHandler);

        $this->assertSame(Status::OK, $response->getStatusCode());
        $this->assertSame('', $requestHandler->processedRequest->getUri()->getHost());
        $this->assertNull($requestHandler->processedRequest->getAttribute('ip', 'default'));
        $this->assertNull($requestHandler->processedRequest->getAttribute('requestClientIp', 'default'));
    }

    public function testWithAttributeIpsAndEmptyString(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Attribute should not be empty string.');
        $this->createTrustedHostsNetworkResolver()->withAttributeIps('');
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
            serverParams: ['REMOTE_ADDR' => '127.0.0.1'],
        );
        $requestHandler = new MockRequestHandler();
        $middleware = $middleware->withAddedTrustedHosts(
            hosts: ['127.0.0.1', '9.9.9.9', $validIp, '2.2.2.2'],
            ipHeaders: [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
            trustedHeaders: ['forwarded'],
        );
        $response = $middleware->process($request, $requestHandler);

        $this->assertSame(Status::OK, $response->getStatusCode());
        $this->assertSame(
            $validIp,
            $requestHandler->processedRequest->getAttribute(TrustedHostsNetworkResolver::REQUEST_CLIENT_IP),
        );
    }

    public function testInvalidTrustedProxy(): void
    {
        $middleware = $this
            ->createTrustedHostsNetworkResolver()
            ->withAttributeIps('resolvedIps')
            ->withAddedTrustedHosts(
                hosts: ['5.5.5.5', '2.2.2.2', '127.0.0.1'],
                ipHeaders: ['x-forwarded-for'],
            );
        $request = $this->createRequestWithSchemaAndHeaders(
            headers: ['x-forwarded-for' => ['9.9.9.9', 'invalid5.5.5.5', '2.2.2.2']],
            serverParams: ['REMOTE_ADDR' => '127.0.0.1'],
        );
        $requestHandler = new MockRequestHandler();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Proxy returned the invalid IP: "invalid5.5.5.5". Check its configuration.');
        $middleware->process($request, $requestHandler);
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
            serverParams: ['REMOTE_ADDR' => '127.0.0.1'],
        );
        $requestHandler = new MockRequestHandler();
        $middleware = $middleware->withAddedTrustedHosts(
            hosts: ['8.8.8.8', '127.0.0.1', '2.2.2.2'],
            ipHeaders: [[TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
            trustedHeaders: ['forwarded'],
        );
        $response = $middleware->process($request, $requestHandler);

        $this->assertSame(Status::OK, $response->getStatusCode());
        $this->assertSame(
            '2.2.2.2',
            $requestHandler->processedRequest->getAttribute(TrustedHostsNetworkResolver::REQUEST_CLIENT_IP),
        );
    }

    public function testOverwrittenIsValidHost(): void
    {
        $middleware = new class (
            new Validator(),
        ) extends TrustedHostsNetworkResolver {
            public function isValidHost(string $host, array $ranges = []): bool
            {
                return $host === '5.5.5.5' ? false : parent::isValidHost($host, $ranges);
            }
        };
        $this->assertFalse($middleware->isValidHost('5.5.5.5'));
        $this->assertTrue($middleware->isValidHost('2.2.2.2'));
    }

    public function testImmutability(): void
    {
        $middleware = $this->createTrustedHostsNetworkResolver();

        $this->assertNotSame($middleware, $middleware->withAddedTrustedHosts(['8.8.8.8']));
        $this->assertNotSame($middleware, $middleware->withoutTrustedHosts());
        $this->assertNotSame($middleware, $middleware->withAttributeIps('test'));
        $this->assertNotSame($middleware, $middleware->withAttributeIps(null));
    }

    private function createRequestWithSchemaAndHeaders(
        string $scheme = 'http',
        array $headers = [],
        array $serverParams = []
    ): ServerRequestInterface {
        $request = new ServerRequest($serverParams);

        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        $uri = $request->getUri()->withScheme($scheme)->withPath('/');
        return $request->withUri($uri);
    }

    private function createTrustedHostsNetworkResolver(): TrustedHostsNetworkResolver
    {
        return (new TrustedHostsNetworkResolver(new Validator()))->withAttributeIps('resolvedIps');
    }

    private function createCustomTrustedHostsNetworkResolver(): TrustedHostsNetworkResolver
    {
        return new class () extends TrustedHostsNetworkResolver {
            public function __construct()
            {
                parent::__construct(new Validator());
            }

            protected function reverseObfuscate(
                ?array $hostData,
                array $hostDataListValidated,
                array $hostDataListRemaining,
                RequestInterface $request
            ): ?array {
                return $hostData['host'] === 'unknown' ? ['ip' => '127.0.0.1'] : $hostData;
            }
        };
    }
}

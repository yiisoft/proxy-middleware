<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Tests\TrustedHostsNetworkResolver;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\Http\Status;
use Yiisoft\ProxyMiddleware\Tests\Support\MockRequestHandler;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;
use Yiisoft\Validator\Validator;

final class ProcessTest extends TestCase
{
    public function dataProcess(): iterable
    {
        return [
            yield 'neither remote addr, nor forwarded headers are set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(),
                [
                    'requestClientIp' => null,
                    'connectionChainItemsAttribute' => ['connectionChainItems', null],
                ],
            ],
            yield 'remote addr not set' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
                ),
                [
                    'requestClientIp' => null,
                    'connectionChainItemsAttribute' => ['connectionChainItems', null],
                ],
            ],
            yield 'remote addr is empty' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '18.18.18.18'])
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
            yield 'forwarded headers not set' => [
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
            yield 'RFC header, empty' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['Forwarded' => ''],
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
            yield 'headers with "X" prefix, empty' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-Forwarded-For' => ''],
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
            yield 'RFC header, no trusted IPs' => [
                $this
                    ->createMiddleware()
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
            yield 'headers with "X" prefix, no trusted IPs' => [
                $this
                    ->createMiddleware()
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

            yield 'RFC header, in request, remote addr in trusted IPs' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['Forwarded' => ['for=9.9.9.9', 'for=5.5.5.5', 'for=2.2.2.2']],
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
                        ],
                    ],
                ],
            ],
            yield 'headers with "X" prefix, in request, remote addr in trusted IPs' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2']],
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
                        ],
                    ],
                ],
            ],
            yield 'forwarded headers are not in request, remote addr in trusted IPs' => [
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
            yield 'RFC header, remote addr and first proxy from request in trusted IPs, header is not allowed' => [
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
            yield 'headers with "X" prefix, remote addr and first proxy from request in trusted IPs, header is not allowed' => [
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
            yield 'RFC header, remote addr and first proxy from request in trusted IPs' => [
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
            yield 'headers with "X" prefix, remote addr and first proxy from request in trusted IPs' => [
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
            yield 'RFC header, remote addr and first 2 proxies from request in trusted IPs' => [
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
            yield 'headers with "X" prefix, remote addr and first 2 proxies from request in trusted IPs' => [
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
            yield 'RFC header, contains IP from private network, IPv4' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '192.168.0.1', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['Forwarded' => ['for=9.9.9.9', 'for=192.168.0.1', 'for=2.2.2.2']],
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
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                ],
            ],
            yield 'headers with "X" prefix, contain IP from private network, IPv4' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '192.168.0.1', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: ['X-Forwarded-For' => ['9.9.9.9', '192.168.0.1', '2.2.2.2']],
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
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                ],
            ],
            yield 'RFC header, contains IP from private network, IPv6' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps([
                        '2001:db8:3333:4444:5555:6666:7777:8888',
                        'fd12:3456:789a:1::1',
                        '2001:db8:3333:4444:5555:6666:7777:2222',
                        '2001:db8:3333:4444:5555:6666:7777:0000',
                    ])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="[2001:db8:3333:4444:5555:6666:7777:9999]"',
                            'for="[fd12:3456:789a:1::1]"',
                            'for="[2001:db8:3333:4444:5555:6666:7777:2222]"',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '2001:db8:3333:4444:5555:6666:7777:0000'],
                ),
                [
                    'requestClientIp' => '2001:db8:3333:4444:5555:6666:7777:2222',
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
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'http',
                    'host' => null,
                    'port' => null,
                ],
            ],
            yield 'headers with "X" prefix, contain IP from private network, IPv6' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps([
                        '2001:db8:3333:4444:5555:6666:7777:8888',
                        'fd12:3456:789a:1::1',
                        '2001:db8:3333:4444:5555:6666:7777:2222',
                        '2001:db8:3333:4444:5555:6666:7777:0000',
                    ])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => [
                            '2001:db8:3333:4444:5555:6666:7777:9999',
                            'fd12:3456:789a:1::1',
                            '2001:db8:3333:4444:5555:6666:7777:2222',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '2001:db8:3333:4444:5555:6666:7777:0000'],
                ),
                [
                    'requestClientIp' => '2001:db8:3333:4444:5555:6666:7777:2222',
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
                                'protocol' => null,
                                'host' => null,
                                'port' => null,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'http',
                    'host' => null,
                    'port' => null,
                ],
            ],

            yield 'RFC header, priority over headers with "X" prefix, IP related data' => [
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
            yield 'headers with "X" prefix, not in request, priority over RFC header, IP related data' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withForwardedHeaderGroups([
                        TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                        TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,
                    ])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host=example2.com',
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
            yield 'RFC header, priority over headers with "X" prefix, IP related data, IPv6 without port' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps([
                        '2001:db8:3333:4444:5555:6666:7777:8888',
                        '2001:db8:3333:4444:5555:6666:7777:2222',
                        '2001:db8:3333:4444:5555:6666:7777:0000',
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
            yield 'RFC header, priority over headers with "X" prefix, IP related data, IPv6 with port' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps([
                        '2001:db8:3333:4444:5555:6666:7777:8888',
                        '2001:db8:3333:4444:5555:6666:7777:2222',
                        '2001:db8:3333:4444:5555:6666:7777:0000',
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
            yield 'headers with "X" prefix, RFC header not in request, IP related data' => [
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
            yield 'custom headers, highest priority, IP related data' => [
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
            yield 'custom headers, IP related data, protocol mapping' => [
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
            yield 'custom headers, IP related data, protocol mapping, protocol header not set' => [
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
            yield 'custom headers, IP related data, protocol mapping, protocol header is empty' => [
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
            yield 'custom headers, IP related data, protocol resolving via callable' => [
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
            yield 'RFC header, IP related data, string keys in trusted IPs and forwarded header groups are ignored' => [
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
            yield 'RFC header, IP related data, case-insensitive' => [
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
            yield 'RFC header, IP related data, min allowed port' => [
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
            yield 'RFC header, IP related data, max allowed port' => [
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
            yield 'RFC header, IP related data, hidden IP, unknown' => [
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
            yield 'RFC header, IP related data, hidden IP, obfuscated, no reverse-obfuscating' => [
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
            yield 'RFC header, IP related data, hidden IP, obfuscated, reverse-obfuscating' => [
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
            yield 'RFC header, IP related data, port in host, priority over port in IP' => [
                $this
                    ->createMiddleware()
                    ->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18'])
                    ->withConnectionChainItemsAttribute('connectionChainItems'),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="5.5.5.5:8082";proto=https;host="example2.com:8085"',
                            'for="2.2.2.2";proto=http;host="example1.com:8084"',
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
                                'port' => 8084,
                                'ipIdentifier' => null,
                            ],
                        ],
                    ],
                    'protocol' => 'https',
                    'host' => 'example2.com',
                    'port' => 8085,
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
}

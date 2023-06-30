<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Tests\TrustedHostsNetworkResolver;

use InvalidArgumentException;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

final class ConfigurationExceptionTest extends TestCase
{
    public function dataWithTrustedIpsException(): array
    {
        return [
            'contains not a string' => [
                ['8.8.8.8', 1, '18.18.18.18'],
                'Trusted IP must be non-empty string.',
            ],
            'contains empty string' => [
                ['8.8.8.8', '', '18.18.18.18'],
                'Trusted IP must be non-empty string.',
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
            'ip: value is empty string' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => '',
                        'protocol' => 'y-forwarded-proto',
                        'host' => 'y-forwarded-host',
                        'port' => 'y-forwarded-port',
                    ],
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
                ],
                'Header name for "ip" must be non-empty string.',
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
            'protocol, array, resolving: name equal to exists function' => [
                [
                    TrustedHostsNetworkResolver::FORWARDED_HEADER_RFC,
                    [
                        'ip' => 'y-forwarded-for',
                        'protocol' => [
                            '\Yiisoft\ProxyMiddleware\Tests\TrustedHostsNetworkResolver\testCallableFunction',
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
        $this->expectExceptionMessage('Attribute can\'t be empty.');
        $middleware->withConnectionChainItemsAttribute('');
    }
}

function testCallableFunction(): void
{
}

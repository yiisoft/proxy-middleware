<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Tests\TrustedHostsNetworkResolver;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use Yiisoft\ProxyMiddleware\Exception\InvalidConnectionChainItemException;
use Yiisoft\ProxyMiddleware\Exception\RfcProxyParseException;
use Yiisoft\ProxyMiddleware\Tests\Support\MockRequestHandler;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;
use Yiisoft\Validator\Validator;

final class RuntimeExceptionTest extends TestCase
{
    public function dataRfcProxyParseException(): iterable
    {
        return [
            yield 'badly formed header value, no double quotes for IP with port' => [
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
            yield 'missing "for" directive' => [
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
            yield 'contains non-allowed directive' => [
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
            yield 'invalid "for" directive' => [
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
                'Contents of "for" directive is invalid.',
            ],
            yield 'IPv6, not exact match, RFC header' => [
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
                            'for="1[2001:db8:3333:4444:5555:6666:7777:5555]2";proto=https;host=example2.com',
                            'for="[2001:db8:3333:4444:5555:6666:7777:2222]";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '2001:db8:3333:4444:5555:6666:7777:0000'],
                ),
                'Contents of "for" directive is invalid.',
            ],
            yield 'not IPv6 enclosed in square brackets' => [
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
            yield 'port, contains non-allowed characters, RFC header' => [
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
                'Contents of "for" directive is invalid.',
            ],
            yield 'port, greater than max, RFC header' => [
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
                'Contents of "for" directive is invalid.',
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
    ): void {
        $requestHandler = new MockRequestHandler();

        $this->expectException(RfcProxyParseException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $middleware->process($request, $requestHandler);
    }

    public function dataInvalidConnectionChainItemException(): iterable
    {
        return [
            yield 'IP, remote addr' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => 'invalid18.18.18.18'],
                ),
                '"invalid18.18.18.18" is not a valid IP.',
            ],
            yield 'IP, RFC header' => [
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
            yield 'IP, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', 'invalid5.5.5.5', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"invalid5.5.5.5" is not a valid IP.',
            ],
            yield 'IP with port, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '5.5.5.5:8082', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"5.5.5.5:8082" is not a valid IP.',
            ],
            yield 'IP identifier, unknown, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', 'unknown', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"unknown" is not a valid IP.',
            ],
            yield 'IP identifier, obfuscated, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '_obfuscated', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"_obfuscated" is not a valid IP.',
            ],
            yield 'IP identifier with port, unknown, RFC header' => [
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
            yield 'IP identifier with port, unknown, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', 'unknown:8082', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"unknown:8082" is not a valid IP.',
            ],
            yield 'IP identifier with port, obfuscated, RFC header' => [
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
            yield 'IP identifier with port, obfuscated, headers with "X" prefix' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'X-Forwarded-For' => ['9.9.9.9', '_obfuscated:8082', '2.2.2.2'],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"_obfuscated:8082" is not a valid IP.',
            ],
            yield 'IP identifier, obfuscated, not exact match, RFC header' => [
                $this->createMiddleware()->withTrustedIps(['8.8.8.8', '2.2.2.2', '18.18.18.18']),
                $this->createRequest(
                    headers: [
                        'Forwarded' => [
                            'for="9.9.9.9:8083";proto=http;host=example3.com',
                            'for="test_obfuscated";proto=https;host=example2.com',
                            'for="2.2.2.2:8081";proto=http;host=example1.com',
                        ],
                    ],
                    serverParams: ['REMOTE_ADDR' => '18.18.18.18'],
                ),
                '"test_obfuscated" is not a valid IP.',
            ],
            yield 'protocol, RFC header' => [
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
            yield 'protocol, headers with "X" prefix' => [
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
            yield 'host, RFC header' => [
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
            yield 'host, headers with "X" prefix' => [
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
            yield 'port, greater than max by 1, RFC header' => [
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
            yield 'port, greater than max within allowed max length, RFC header' => [
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
            yield 'port, less than min by 1, RFC header' => [
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
            yield 'port, greater than max, headers with "X" prefix' => [
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
    ): void {
        $requestHandler = new MockRequestHandler();

        $this->expectException(InvalidConnectionChainItemException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $middleware->process($request, $requestHandler);
    }

    public function dataGetProtocolException(): iterable
    {
        return [
            yield 'mapping, no matching item' => [
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
            yield 'callable, return value is null' => [
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
            yield 'callable, return value is not a valid protocol' => [
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
    ): void {
        $requestHandler = new MockRequestHandler();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $middleware->process($request, $requestHandler);
    }

    public function dataReverseObfuscateIpIdentifierException(): iterable
    {
        return [
            yield 'empty array' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array {
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
            yield 'wrong items count' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array {
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
            yield 'IP: not a string' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array {
                        return [1, '8081'];
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
            yield 'IP: empty string' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array {
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
            yield 'IP: invalid' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array {
                        return ['invalid5.5.5.5', '8081'];
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
                'IP returned from reverse-obfuscated IP data is not valid.',
            ],
            yield 'port: empty string' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array {
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
            yield 'IP: valid port instead of IP, port: invalid' => [
                (new class (new Validator()) extends TrustedHostsNetworkResolver {
                    protected function reverseObfuscateIpIdentifier(
                        string $ipIdentifier,
                        array $validatedConnectionChainItems,
                        array $remainingConnectionChainItems,
                        RequestInterface $request,
                    ): ?array {
                        return ['8082', '0'];
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
                'Port returned from reverse-obfuscated IP data is not valid.',
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
    ): void {
        $requestHandler = new MockRequestHandler();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $middleware->process($request, $requestHandler);
    }
}

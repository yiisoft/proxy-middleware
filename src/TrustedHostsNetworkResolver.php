<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware;

use InvalidArgumentException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RuntimeException;
use Yiisoft\Http\HeaderValueHelper;
use Yiisoft\NetworkUtilities\IpHelper;
use Yiisoft\ProxyMiddleware\Exception\HeaderValueParseException;
use Yiisoft\ProxyMiddleware\Exception\InvalidConnectionChainItemException;
use Yiisoft\ProxyMiddleware\Exception\InvalidRfcProxyItemException;
use Yiisoft\Validator\Rule\Ip;
use Yiisoft\Validator\ValidatorInterface;

/**
 * Trusted hosts network resolver can set IP, protocol, host, URL, and port based on trusted headers such as
 * `Forward` or `X-Forwarded-Host` coming from trusted hosts you define. Usually these are load balancers.
 *
 * Make sure that the trusted host always overwrites or removes user-defined headers
 * to avoid security issues.
 *
 * @psalm-type ConnectionChainItem = array{
 *     ip: ?string,
 *     protocol: ?string,
 *     host: ?string,
 *     port: ?int,
 *     hiddenIp: ?string,
 *     hiddenPort: ?string,
 * }
 * @psalm-type ProtocolHeadersData = array<string, array<non-empty-string, array<array-key, string>>|callable>
 */
class TrustedHostsNetworkResolver implements MiddlewareInterface
{
    public const FORWARDED_HEADER_RFC = 'forwarded';
    public const FORWARDED_HEADER_GROUP_RFC = self::FORWARDED_HEADER_RFC;
    public const FORWARDED_HEADER_GROUP_X_PREFIX = [
        'ip' => 'x-forwarded-for',
        'protocol' => 'x-forwarded-proto',
        'host' => 'x-forwarded-host',
        'port' => 'x-forwarded-port',
    ];
    public const DEFAULT_FORWARDED_HEADER_GROUPS = [
        self::FORWARDED_HEADER_GROUP_RFC,
        self::FORWARDED_HEADER_GROUP_X_PREFIX,
    ];
    /**
     * List of headers to trust for any trusted host.
     */
    public const TYPICAL_FORWARDED_HEADERS = [
        // RFC
        'forwarded',

        // "X" prefix
        'x-forwarded-for',
        'x-forwarded-host',
        'x-forwarded-proto',
        'x-forwarded-port',

        // Microsoft
        'front-end-https',
    ];
    /**
     * Name of the request attribute holding IP address obtained from a trusted header.
     */
    public const ATTRIBUTE_REQUEST_CLIENT_IP = 'requestClientIp';

    private const PROTOCOL_HTTP = 'http';
    private const PROTOCOL_HTTPS = 'https';
    private const ALLOWED_PROTOCOLS = [self::PROTOCOL_HTTP, self::PROTOCOL_HTTPS];

    private array $trustedIps = [];
    private array $forwardedHeaderGroups = self::DEFAULT_FORWARDED_HEADER_GROUPS;
    private array $typicalForwardedHeaders = self::TYPICAL_FORWARDED_HEADERS;
    private ?string $connectionChainItemsAttribute = null;

    public function __construct(private ValidatorInterface $validator)
    {
    }

    public function withTrustedIps(array $trustedIps): self {
        $this->assertNonEmpty($trustedIps, 'Trusted IPs');

        foreach ($trustedIps as $host) {
            if (!$this->checkIp($host)) {
                throw new InvalidArgumentException("\"$host\" is not a valid IP.");
            }
        }

        $new = clone $this;
        $new->trustedIps = $trustedIps;

        return $new;
    }

    public function withForwardedHeaderGroups(array $headerGroups): self
    {
        $this->assertNonEmpty($headerGroups, 'Forwarded header groups');

        $allowedHeaderGroupKeys = ['ip', 'protocol', 'host', 'port'];
        foreach ($headerGroups as $headerGroup) {
            if (is_array($headerGroup)) {
                $this->assertNonEmpty($headerGroup, 'Forwarded header group array');
                $this->assertExactKeysForArray($allowedHeaderGroupKeys, $headerGroup, 'forwarded header group');

                foreach (['ip', 'host', 'port'] as $key) {
                    $this->assertIsNonEmptyString($headerGroup[$key], "Header name for \"$key\"");
                }

                if (is_string($headerGroup['protocol'])) {
                    $this->assertNonEmpty($headerGroup['protocol'], 'Header name for "protocol"');
                } elseif (is_array($headerGroup['protocol'])) {
                    $this->assertNonEmpty($headerGroup['protocol'], 'Protocol header config array');
                    $this->assertExactKeysForArray([0, 1], $headerGroup['protocol'], 'protocol header config');
                    $this->assertIsNonEmptyString($headerGroup['protocol'][0], 'Header name for "protocol"');

                    if (is_array($headerGroup['protocol'][1])) {
                        $this->assertNonEmpty($headerGroup['protocol'][1], 'Values in mapping for protocol header');

                        foreach ($headerGroup['protocol'][1] as $key => $value) {
                            $this->assertIsNonEmptyString($key, 'Key in mapping for protocol header');
                            $this->assertIsAllowedProtocol($value, 'Value in mapping for protocol header');
                        }
                    } elseif(!is_callable($headerGroup['protocol'][1])) {
                        $message = 'Protocol header resolving must be specified either via an associative array or a ' .
                            'callable.';

                        throw new InvalidArgumentException($message);
                    }
                } else {
                    throw new InvalidArgumentException('Protocol header config must be either a string or an array.');
                }

                continue;
            }

            if ($headerGroup !== self::FORWARDED_HEADER_GROUP_RFC) {
                $message = 'Forwarded header group must be either an associative array or '.
                    'TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC constant.';

                throw new InvalidArgumentException($message);
            }
        }

        $new = clone $this;
        $new->forwardedHeaderGroups = $headerGroups;
        return $new;
    }

    public function withTypicalForwardedHeaders(array $headerNames): self
    {
        $this->assertNonEmpty($headerNames, 'Typical forwarded headers');

        foreach ($headerNames as $headerName) {
            $this->assertIsNonEmptyString($headerName, 'Typical forwarded header');
        }

        $new = clone $this;
        $new->typicalForwardedHeaders = $headerNames;
        return $new;
    }

    /**
     * Returns a new instance with the specified request's attribute name to which middleware writes trusted path data.
     *
     * @param string|null $attribute The request attribute name.
     */
    public function withConnectionChainItemsAttribute(?string $attribute): self
    {
        if ($attribute === '') {
            throw new InvalidArgumentException('Attribute can\'t be empty string.');
        }

        $new = clone $this;
        $new->connectionChainItemsAttribute = $attribute;
        return $new;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // TODO: Remove non-typical forwarded headers.

        $connectionChainItems = $this->getConnectionChainItems($request);
        if (empty($connectionChainItems)) {
            return $this->handleNotTrusted($request, $handler);
        }

        $validatedConnectionChainItems = [];
        $connectionChainItem = $this->iterateConnectionChainItems(
            $connectionChainItems,
            $validatedConnectionChainItems,
            $request,
        );
        if ($connectionChainItem === null) {
            return $this->handleNotTrusted($request, $handler);
        }

        if ($this->connectionChainItemsAttribute !== null) {
            $request = $request->withAttribute($this->connectionChainItemsAttribute, $validatedConnectionChainItems);
        }

        $uri = $request->getUri();

        $protocol = $connectionChainItem['protocol'];
        if ($protocol !== null) {
            $uri = $uri->withScheme($protocol);
        }

        $host = $connectionChainItem['host'];
        if ($host !== null) {
            $uri = $uri->withHost($host);
        }

        $port = $connectionChainItem['port'];
        if ($port !== null) {
            $uri = $uri->withPort((int) $port);
        }

        $request = $request
            ->withUri($uri)
            ->withAttribute(self::ATTRIBUTE_REQUEST_CLIENT_IP, $connectionChainItem['ip']);

        return $handler->handle($request);
    }

    /**
     * Reverse obfuscating host data
     *
     * RFC 7239 allows using obfuscated host data. In this case, either specifying the
     * IP address or dropping the proxy endpoint is required to determine validated route.
     *
     * By default, it doesn't perform any transformation on the data. You can override this method.
     *
     * @return array|null reversed obfuscated host data or null.
     * In case of `null` data is discarded, and the process continues with the next portion of host data.
     * If the return value is an array, it must contain at least the `ip` key.
     *
     * @psalm-param HostData|null $hostData
     *
     * @psalm-return HostData|null
     *
     * @see parseProxiesFromRfcHeader()
     * @link https://tools.ietf.org/html/rfc7239#section-6.2
     * @link https://tools.ietf.org/html/rfc7239#section-6.3
     */
    protected function reverseObfuscateIp(
        string $hiddenIp,
        array $validatedConnectionChainItems,
        array $remainingConnectionChainItems,
        RequestInterface $request,
    ): ?string {
        return null;
    }

    protected function reverseObfuscatePort(
        string $hiddenPort,
        array $validatedConnectionChainItems,
        array $remainingConnectionChainItems,
        RequestInterface $request,
    ): ?string {
        return null;
    }

    /**
     * Validate whether a given string is a valid IP address and whether it's included in given ranges (optional).
     *
     * You can overwrite this method in a subclass to support reverse DNS verification.
     *
     * @param string $value Value to validate.
     * @param string[] $ranges The IPv4 or IPv6 ranges that are allowed or forbidden (see {@see Ip::$ranges}}.
     *
     * @return bool Whether the validation was successful.
     */
    protected function checkIp(string $value, array $ranges = []): bool
    {
        return $this
            ->validator
            ->validate($value, [new Ip(ranges: $ranges)])
            ->isValid();
    }

    private function assertNonEmpty(mixed $value, string $name): void
    {
        if (empty($value)) {
            throw new InvalidArgumentException("$name can't be empty.");
        }
    }

    private function assertExactKeysForArray(array $allowedKeys, array $array, string $name): void
    {
        if (array_keys($array) === $allowedKeys) {
            return;
        }

        $allowedKeysStr = implode('", "', $allowedKeys);
        $message = "Invalid array keys for $name. The allowed and required keys are: \"$allowedKeysStr\".";

        throw new InvalidArgumentException($message);
    }

    /**
     * @psalm-assert non-empty-string $value
     */
    private function assertIsNonEmptyString(mixed $value, string $name): void
    {
        if (!is_string($value) || $value === '') {
            throw new InvalidArgumentException("$name must be non-empty string.");
        }
    }

    private function assertIsAllowedProtocol(
        mixed $value,
        string $name,
        string $expeptionClassName = InvalidArgumentException::class,
    ): void
    {
        $this->assertIsNonEmptyString($value, $name);

        if ($this->checkProtocol($value)) {
            return;
        }

        $allowedProtocolsStr = implode('", "', self::ALLOWED_PROTOCOLS);
        $message = "$name must be a valid protocol. Allowed values are: \"$allowedProtocolsStr\" (case-sensitive).";

        throw new $expeptionClassName($message);
    }

    private function handleNotTrusted(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        if ($this->connectionChainItemsAttribute !== null) {
            $request = $request->withAttribute($this->connectionChainItemsAttribute, null);
        }

        return $handler->handle($request->withAttribute(self::ATTRIBUTE_REQUEST_CLIENT_IP, null));
    }

    /**
     * @param string[] $headers
     */
    private function removeHeaders(ServerRequestInterface $request, array $headers): ServerRequestInterface
    {
        foreach ($headers as $header) {
            $request = $request->withoutHeader($header);
        }

        return $request;
    }

    private function getConnectionChainItems(ServerRequestInterface $request): array
    {
        /** @var string|null $remoteAddr */
        $remoteAddr = $request->getServerParams()['REMOTE_ADDR'] ?? null;
        if ($remoteAddr === null) {
            return [];
        }

        $items = [
            [
                'ip' => $remoteAddr,
                'protocol' => null,
                'host' => null,
                'port' => null,
                'hiddenIp' => null,
                'hiddenPort' => null,
            ],
        ];
        foreach ($this->forwardedHeaderGroups as $forwardedHeaderGroup) {
            if ($forwardedHeaderGroup === self::FORWARDED_HEADER_GROUP_RFC) {
                if (!$request->hasHeader(self::FORWARDED_HEADER_RFC)) {
                    continue;
                }

                $forwardedHeaderValue = $request->getHeader(self::FORWARDED_HEADER_RFC);
                $items = [...$items, ...array_reverse($this->parseProxiesFromRfcHeader($forwardedHeaderValue))];

                break;
            }

            if (!$request->hasHeader($forwardedHeaderGroup['ip'])) {
                continue;
            }

            $items = [];
            $requestIps = array_merge([$remoteAddr], array_reverse($request->getHeader($forwardedHeaderGroup['ip'])));
            foreach ($requestIps as $requestIp) {
                $items[] = [
                    'ip' => $requestIp,
                    'protocol' => $this->getProtocol($request, $forwardedHeaderGroup['protocol']),
                    'host' => $request->getHeaderLine($forwardedHeaderGroup['host']) ?: null,
                    'port' => $request->getHeaderLine($forwardedHeaderGroup['port']) ?: null,
                    'hiddenIp' => null,
                    'hiddenPort' => null,
                ];
            }

            break;
        }

        return $items;
    }

    /**
     * Forwarded elements by RFC7239.
     *
     * The structure of the elements:
     * - `host`: IP or obfuscated hostname or "unknown"
     * - `ip`: IP address (only if present)
     * - `port`: port number received by proxy (only if present)
     * - `protocol`: protocol received by proxy (only if present)
     * - `host`: HTTP host received by proxy (only if present)
     *
     * The list starts with the server, and the last item is the client itself.
     *
     * @link https://tools.ietf.org/html/rfc7239
     *
     * @param string[] $proxyItems
     *
     * @psalm-return list<HostData> Proxy data elements.
     */
    private function parseProxiesFromRfcHeader(array $proxyItems): array
    {
        $proxies = [];
        foreach ($proxyItems as $proxyItem) {
            try {
                /** @psalm-var array<string, string> $directiveMap */
                $directiveMap = HeaderValueHelper::getParameters($proxyItem);
            } catch (InvalidArgumentException $exception) {
                $message = "Unable to parse header value: \"$proxyItem\". {$exception->getMessage()}";

                throw new HeaderValueParseException($message);
            }

            if (!isset($directiveMap['for'])) {
                throw new InvalidRfcProxyItemException();
            }

            foreach ($directiveMap as $name => $value) {
                if (!in_array($name, ['by', 'for', 'proto', 'host'])) {
                    throw new InvalidRfcProxyItemException();
                }
            }

            // TODO: Should port be parsed from host instead?
            // TODO: Matches contains empty strings.
            $pattern = '/^(?<ip>' . IpHelper::IPV4_PATTERN . '|unknown|_[\w.-]+|' .
                '[[]' . IpHelper::IPV6_PATTERN . '[]])(?::(?<port>[\w.-]+))?$/';
            if (preg_match($pattern, $directiveMap['for'], $matches) === 0) {
                throw new InvalidRfcProxyItemException();
            }

            $ip = $matches['ip'];
            $protocol = $directiveMap['proto'] ?? null;
            $host = $directiveMap['host'] ?? null;
            $port = $matches['port'] ?? null;

            if ($ip === 'unknown' || str_starts_with($ip, '_')) {
                $proxies[] = [
                    'ip' => null,
                    'protocol' => $protocol,
                    'host' => $host,
                    'port' => null,
                    'hiddenIp' => $ip,
                    'hiddenPort' => $port,
                ];

                continue;
            }

            $proxies[] = [
                'ip' => $ip,
                'protocol' => $protocol,
                'host' => $host,
                'port' => $port,
                'hiddenIp' => null,
                'hiddenPort' => null,
            ];
        }

        return $proxies;
    }

    private function getProtocol(ServerRequestInterface $request, string|array|callable $configValue): ?string
    {
        if (is_string($configValue)) {
            return $request->getHeaderLine($configValue) ?: null;
        }

        $headerName = $configValue[0];
        $initialProtocol = $request->getHeaderLine($headerName);
        if ($initialProtocol === '') {
            return null;
        }

        if (is_array($configValue[1])) {
            $protocol = $configValue[1][$initialProtocol] ?? null;
            if ($protocol === null) {
                throw new RuntimeException("Unable to resolve \"$protocol\" protocol via mapping.");
            }
        } else {
            $resolveProtocolCallable = $configValue[1];
            $protocol = $resolveProtocolCallable($initialProtocol);
            if ($protocol === null) {
                throw new RuntimeException("Unable to resolve \"$protocol\" protocol via callable.");
            }

            $this->assertIsAllowedProtocol(
                $protocol,
                'Value returned from callable for protocol header',
                RuntimeException::class,
            );
        }

        return $protocol;
    }

    private function iterateConnectionChainItems(
        array $items,
        array &$validatedItems,
        ServerRequestInterface $request,
    ): ?array
    {
        $item = null;
        $remainingItems = $items;
        $proxiesCount = 0;

        do {
            $proxiesCount++;

            $rawItem = array_shift($remainingItems);
            if ($rawItem['hiddenIp'] !== null) {
                $ip = $this->reverseObfuscateIp($rawItem['hiddenIp'], $validatedItems, $remainingItems, $request);
                if ($ip !== null) {
                    $rawItem['ip'] = $ip;
                }
            }

            if ($rawItem['hiddenPort'] !== null) {
                $port = $this->reverseObfuscatePort($rawItem['hiddenPort'], $validatedItems, $remainingItems, $request);
                if ($port !== null) {
                    $rawItem['port'] = $port;
                }
            }

            $ip = $rawItem['ip'];
            if ($ip !== null && !$this->checkIp($ip)) {
                throw new InvalidConnectionChainItemException("\"$ip\" is not a valid IP.");
            }

            $protocol = $rawItem['protocol'];
            if ($protocol !== null && !$this->checkProtocol($protocol)) {
                $allowedProtocolsStr = implode('", "', self::ALLOWED_PROTOCOLS);
                $message = "\"$protocol\" protocol is not allowed. Allowed values are: \"$allowedProtocolsStr\" " .
                    '(case-sensitive).';

                throw new InvalidConnectionChainItemException($message);
            }

            $host = $rawItem['host'];
            if ($host !== null && !$this->checkHost($host)) {
                throw new InvalidConnectionChainItemException("\"$host\" is not a valid host.");
            }

            $port = $rawItem['port'];
            if ($port !== null) {
                if (!$this->checkPort($port)) {
                    throw new InvalidConnectionChainItemException("\"$port\" is not a valid port.");
                }

                $rawItem['port'] = (int) $port;
            }

            if ($proxiesCount >= 3) {
                $item = $rawItem;
            }

            if (!$this->checkIp($ip, $this->trustedIps)) {
                break;
            }

            $item = $rawItem;
            $validatedItems[] = $item;
        } while (count($remainingItems) > 0);

        return $item;
    }

    private function checkProtocol(string $protocol): bool
    {
        return in_array($protocol, self::ALLOWED_PROTOCOLS);
    }

    private function checkHost(string $host): bool
    {
        return filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }

    private function checkPort(string $port): bool
    {
        /**
         * @infection-ignore-all
         * - PregMatchRemoveCaret.
         * - PregMatchRemoveDollar.
         */
        if (preg_match('/^\d{1,5}$/', $port) !== 1) {
            return false;
        }

        /** @infection-ignore-all CastInt */
        $intPort = (int) $port;

        return $intPort >= 1 && $intPort <= 65535;
    }
}

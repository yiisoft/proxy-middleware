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
use Yiisoft\ProxyMiddleware\Exception\InvalidConnectionChainItemException;
use Yiisoft\ProxyMiddleware\Exception\RfcProxyParseException;
use Yiisoft\Validator\Rule\Ip;
use Yiisoft\Validator\ValidatorInterface;

/**
 * @psalm-type ProtocolResolvingMapping = array<non-empty-string, TrustedHostsNetworkResolver::PROTOCOL_*>
 * @psalm-type ProtocolResolvingCallable = Closure(non-empty-string): ?non-empty-string
 * @psalm-type ProtocolConfig = lowercase-string | array{0: lowercase-string, 1: ProtocolResolvingMapping | ProtocolResolvingCallable}
 * @psalm-type SeparateForwardedHeaderGroup = array{
 *     ip: lowercase-string,
 *     protocol: ProtocolConfig,
 *     host: lowercase-string,
 *     port: lowercase-string,
 * }
 * @psalm-type ForwardedHeaderGroups = list<TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC | SeparateForwardedHeaderGroup>
 *
 * @psalm-type RawConnectionChainItem = array{
 *     ip: ?non-empty-string,
 *     protocol: ?TrustedHostsNetworkResolver::PROTOCOL_*,
 *     host: ?non-empty-string,
 *     port: ?int,
 *     ipIdentifier: ?non-empty-string,
 * }
 * @psalm-type ConnectionChainItem = array{
 *     ip: non-empty-string,
 *     protocol: ?TrustedHostsNetworkResolver::PROTOCOL_*,
 *     host: ?non-empty-string,
 *     port: ?int,
 *     ipIdentifier: ?non-empty-string,
 * }
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

    public const ATTRIBUTE_REQUEST_CLIENT_IP = 'requestClientIp';

    private const ALLOWED_RFC_HEADER_DIRECTIVES = ['by', 'for', 'proto', 'host'];

    private const PROTOCOL_HTTP = 'http';
    private const PROTOCOL_HTTPS = 'https';
    private const ALLOWED_PROTOCOLS = [self::PROTOCOL_HTTP, self::PROTOCOL_HTTPS];

    private const PORT_MIN = 1;
    private const PORT_MAX = 65535;

    /**
     * @psalm-var list<non-empty-string>
     * @psalm-suppress PropertyNotSetInConstructor
     */
    private array $trustedIps;
    /**
     * @psalm-var ForwardedHeaderGroups
     */
    private array $forwardedHeaderGroups = self::DEFAULT_FORWARDED_HEADER_GROUPS;
    /**
     * @psalm-var list<lowercase-string>
     */
    private array $typicalForwardedHeaders = self::TYPICAL_FORWARDED_HEADERS;
    /**
     * @psalm-var ?non-empty-string
     */
    private ?string $connectionChainItemsAttribute = null;

    public function __construct(private ValidatorInterface $validator)
    {
    }

    public function withTrustedIps(array $trustedIps): self
    {
        $this->assertNonEmpty($trustedIps, 'Trusted IPs');

        $validatedIps = [];
        foreach ($trustedIps as $ip) {
            if (!$this->checkIp($ip)) {
                throw new InvalidArgumentException("\"$ip\" is not a valid IP.");
            }

            $validatedIps[] = $ip;
        }

        $new = clone $this;
        $new->trustedIps = $validatedIps;

        return $new;
    }

    public function withForwardedHeaderGroups(array $headerGroups): self
    {
        $this->assertNonEmpty($headerGroups, 'Forwarded header groups');

        $allowedHeaderGroupKeys = ['ip', 'protocol', 'host', 'port'];
        foreach ($headerGroups as $index => $headerGroup) {
            if (is_array($headerGroup)) {
                $this->assertNonEmpty($headerGroup, 'Forwarded header group array');
                $this->assertExactKeysForArray($allowedHeaderGroupKeys, $headerGroup, 'forwarded header group');

                foreach (['ip', 'host', 'port'] as $key) {
                    $this->assertIsNonEmptyString($headerGroup[$key], "Header name for \"$key\"");
                    $headerGroups[$index][$key] = $this->normalizeHeaderName($headerGroup[$key]);
                }

                if (is_string($headerGroup['protocol'])) {
                    $this->assertNonEmpty($headerGroup['protocol'], 'Header name for "protocol"');
                    $headerGroups[$index]['protocol'] = $this->normalizeHeaderName($headerGroup['protocol']);
                } elseif (is_array($headerGroup['protocol'])) {
                    $this->assertNonEmpty($headerGroup['protocol'], 'Protocol header config array');
                    $this->assertExactKeysForArray([0, 1], $headerGroup['protocol'], 'protocol header config');
                    $this->assertIsNonEmptyString($headerGroup['protocol'][0], 'Header name for "protocol"');
                    $headerGroups[$index]['protocol'][0] = $this->normalizeHeaderName($headerGroup['protocol'][0]);

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
        /** @psalm-var ForwardedHeaderGroups forwardedHeaderGroups */
        $new->forwardedHeaderGroups = $headerGroups;
        return $new;
    }

    public function withTypicalForwardedHeaders(array $headerNames): self
    {
        $this->assertNonEmpty($headerNames, 'Typical forwarded headers');

        $normalizedHeaderNames = [];
        foreach ($headerNames as $headerName) {
            $this->assertIsNonEmptyString($headerName, 'Typical forwarded header');
            $normalizedHeaderNames[] = $this->normalizeHeaderName($headerName);
        }

        $new = clone $this;
        $new->typicalForwardedHeaders = $normalizedHeaderNames;
        return $new;
    }

    public function withConnectionChainItemsAttribute(?string $attribute): self
    {
        // TODO: Use assert.
        if ($attribute === '') {
            throw new InvalidArgumentException('Attribute can\'t be empty string.');
        }

        $new = clone $this;
        $new->connectionChainItemsAttribute = $attribute;
        return $new;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /** @var string|null $remoteAddr */
        $remoteAddr = $request->getServerParams()['REMOTE_ADDR'] ?? null;
        if (empty($remoteAddr)) {
            return $this->handleNotTrusted($request, $handler);
        }

        $request = $this->filterTypicalForwardedHeaders($request);

        $connectionChainItems = $this->getConnectionChainItems($remoteAddr, $request);
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
            $uri = $uri->withPort($port);
        }

        $request = $request
            ->withUri($uri)
            ->withAttribute(self::ATTRIBUTE_REQUEST_CLIENT_IP, $connectionChainItem['ip']);

        return $handler->handle($request);
    }

    /**
     * @psalm-param non-empty-string $ipIdentifier
     * @psalm-param list<ConnectionChainItem> $validatedConnectionChainItems
     * @psalm-param list<RawConnectionChainItem> $remainingConnectionChainItems
     *
     * @see parseProxiesFromRfcHeader()
     * @link https://tools.ietf.org/html/rfc7239#section-6.2
     * @link https://tools.ietf.org/html/rfc7239#section-6.3
     */
    protected function reverseObfuscateIpIdentifier(
        string $ipIdentifier,
        array $validatedConnectionChainItems,
        array $remainingConnectionChainItems,
        RequestInterface $request,
    ): ?array {
        return null;
    }

    /**
     * @psalm-param non-empty-string $name
     */
    private function assertNonEmpty(string|array $value, string $name, bool $inRuntime = false): void
    {
        if (!empty($value)) {
            return;
        }

        $expeptionClassName = $inRuntime ? RuntimeException::class : InvalidArgumentException::class;

        throw new $expeptionClassName("$name can't be empty.");
    }

    /**
     * @psalm-param list<int | string> $allowedKeys
     * @psalm-param non-empty-string $name
     */
    private function assertExactKeysForArray(
        array $allowedKeys,
        array $array,
        string $name,
        bool $inRuntime = false,
    ): void
    {
        if (array_keys($array) === $allowedKeys) {
            return;
        }

        $allowedKeysStr = implode('", "', $allowedKeys);
        $message = "Invalid array keys for $name. The allowed and required keys are: \"$allowedKeysStr\".";
        $expeptionClassName = $inRuntime ? RuntimeException::class : InvalidArgumentException::class;

        throw new $expeptionClassName($message);
    }

    /**
     * @psalm-assert non-empty-string $value
     * @psalm-param non-empty-string $name
     */
    private function assertIsNonEmptyString(mixed $value, string $name, bool $inRuntime = false): void
    {
        if (is_string($value) && $value !== '') {
            return;
        }

        $expeptionClassName = $inRuntime ? RuntimeException::class : InvalidArgumentException::class;

        throw new $expeptionClassName("$name must be non-empty string.");
    }

    /**
     * @psalm-assert TrustedHostsNetworkResolver::PROTOCOL_* $value
     * @psalm-param non-empty-string $name
     */
    private function assertIsAllowedProtocol(mixed $value, string $name, bool $inRuntime = false): void
    {
        $this->assertIsNonEmptyString($value, $name);

        if ($this->checkProtocol($value)) {
            return;
        }

        $allowedProtocolsStr = implode('", "', self::ALLOWED_PROTOCOLS);
        $message = "$name must be a valid protocol. Allowed values are: \"$allowedProtocolsStr\" (case-sensitive).";
        $expeptionClassName = $inRuntime ? RuntimeException::class : InvalidArgumentException::class;

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

    private function filterTypicalForwardedHeaders(ServerRequestInterface $request): ServerRequestInterface
    {
        $headers = array_diff($this->typicalForwardedHeaders, $this->getTrustedForwardedHeaders());
        foreach ($headers as $header) {
            $request = $request->withoutHeader($header);
        }

        return $request;
    }

    /**
     * @psalm-return list<lowercase-string>
     */
    private function getTrustedForwardedHeaders(): array
    {
        $headers = [];
        foreach ($this->forwardedHeaderGroups as $headerGroup) {
            if (is_string($headerGroup)) {
                $headers[] = $headerGroup;

                continue;
            }

            $headers[] = $headerGroup['ip'];
            $headers[] = is_string($headerGroup['protocol']) ? $headerGroup['protocol'] : $headerGroup['protocol'][0];
            $headers[] = $headerGroup['host'];
            $headers[] = $headerGroup['port'];
        }

        return $headers;
    }

    /**
     * @psalm-return lowercase-string
     */
    private function normalizeHeaderName(string $headerName): string
    {
        return strtolower($headerName);
    }

    /**
     * @psalm-param non-empty-string $remoteAddr
     *
     * @psalm-return list<RawConnectionChainItem>
     */
    private function getConnectionChainItems(string $remoteAddr, ServerRequestInterface $request): array
    {
        $items = [$this->getConnectionChainItem(ip: $remoteAddr)];
        foreach ($this->forwardedHeaderGroups as $forwardedHeaderGroup) {
            if ($forwardedHeaderGroup === self::FORWARDED_HEADER_GROUP_RFC) {
                /** @psalm-var list<string> $forwardedHeaderValue */
                $forwardedHeaderValue = $request->getHeader(self::FORWARDED_HEADER_RFC);
                if (empty($forwardedHeaderValue) || empty($request->getHeaderLine(self::FORWARDED_HEADER_RFC))) {
                    continue;
                }

                $items = [...$items, ...array_reverse($this->parseProxiesFromRfcHeader($forwardedHeaderValue))];

                break;
            }

            /** @psalm-var list<string> $forwardedHeaderValue */
            $forwardedHeaderValue = $request->getHeader($forwardedHeaderGroup['ip']);
            if (empty($forwardedHeaderValue) || empty($request->getHeaderLine($forwardedHeaderGroup['ip']))) {
                continue;
            }

            $items = [];
            $requestIps = array_merge([$remoteAddr], array_reverse($forwardedHeaderValue));
            foreach ($requestIps as $requestIp) {
                $items[] = $this->getConnectionChainItem(
                    ip: $requestIp,
                    protocol: $this->getProtocolFromSeparateHeader($request, $forwardedHeaderGroup['protocol']),
                    host: $request->getHeaderLine($forwardedHeaderGroup['host']) ?: null,
                    port: $request->getHeaderLine($forwardedHeaderGroup['port']) ?: null,
                    validateProtocol: !is_array($forwardedHeaderGroup['protocol']),
                );
            }

            break;
        }

        return $items;
    }

    /**
     * @psalm-param ProtocolConfig $configValue
     */
    private function getProtocolFromSeparateHeader(
        ServerRequestInterface $request,
        string|array $configValue,
    ): ?string
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
                throw new RuntimeException("Unable to resolve \"$initialProtocol\" protocol via mapping.");
            }
        } else {
            $resolveProtocolCallable = $configValue[1];
            $protocol = $resolveProtocolCallable($initialProtocol);
            if ($protocol === null) {
                throw new RuntimeException("Unable to resolve \"$initialProtocol\" protocol via callable.");
            }

            $this->assertIsAllowedProtocol(
                $protocol,
                'Value returned from callable for protocol header',
                inRuntime: true,
            );
        }

        // TODO: Add validation flag.

        return $protocol;
    }

    /**
     * @psalm-param list<string> $proxyItems
     *
     * @psalm-return list<RawConnectionChainItem>
     *
     * @link https://tools.ietf.org/html/rfc7239
     */
    private function parseProxiesFromRfcHeader(array $proxyItems): array
    {
        $proxies = [];
        foreach ($proxyItems as $proxyItem) {
            try {
                /** @psalm-var array<string, string> $directiveMap */
                $directiveMap = HeaderValueHelper::getParameters($proxyItem);
            } catch (InvalidArgumentException) {
                throw new RfcProxyParseException("Unable to parse RFC header value: \"$proxyItem\".");
            }

            if (!isset($directiveMap['for'])) {
                throw new RfcProxyParseException('"for" directive is required.');
            }

            foreach ($directiveMap as $name => $value) {
                if (!in_array($name, self::ALLOWED_RFC_HEADER_DIRECTIVES)) {
                    $allowedDirectivesStr = implode('", "', self::ALLOWED_RFC_HEADER_DIRECTIVES);
                    $message = "\"$name\" is not a valid directive. Allowed values are: \"$allowedDirectivesStr\" " .
                        '(case-insensitive).';

                    throw new RfcProxyParseException($message);
                }
            }

            $wasIpValidated = false;

            if ($this->checkIpIdentifier($directiveMap['for'])) {
                $ip = null;
                $port = null;
                $ipIdentifier = $directiveMap['for'];
            } else {
                if (preg_match('/^\[(?<ip>.+)](?::(?<port>\d{1,5}+))?$/', $directiveMap['for'], $matches)) {
                    $ip = $matches['ip'];
                    if (!$this->checkIpv6($ip)) {
                        $message = "Enclosing in square brackets assumes presence of valid IPv6, \"$ip\" given.";

                        throw new RfcProxyParseException($message);
                    }

                    $port = $matches['port'] ?? null;
                    $wasIpValidated = true;
                } else {
                    $ipData = explode(':', $directiveMap['for'], 2);
                    $ip = $ipData[0];
                    if ($ip === '') {
                        throw new RfcProxyParseException('IP is missing in "for" directive.');
                    }

                    $port = $ipData[1] ?? null;
                }

                $ipIdentifier = null;
            }

            $proxies[] = $this->getConnectionChainItem(
                ip: $ip,
                protocol: $directiveMap['proto'] ?? null,
                host: $directiveMap['host'] ?? null,
                port: $port,
                ipIdentifier: $ipIdentifier,
                validateIp: !$wasIpValidated,
            );
        }

        return $proxies;
    }

    /**
     * @psalm-return RawConnectionChainItem
     */
    private function getConnectionChainItem(
        ?string $ip = null,
        ?string $protocol = null,
        ?string $host = null,
        ?string $port = null,
        ?string $ipIdentifier = null,
        bool $validateIp = true,
        bool $validateProtocol = true,
    ): array
    {
        if ($ip !== null && $validateIp && !$this->checkIp($ip)) {
            throw new InvalidConnectionChainItemException("\"$ip\" is not a valid IP.");
        }

        if ($protocol !== null && $validateProtocol && !$this->checkProtocol($protocol)) {
            $allowedProtocolsStr = implode('", "', self::ALLOWED_PROTOCOLS);
            $message = "\"$protocol\" protocol is not allowed. Allowed values are: \"$allowedProtocolsStr\" " .
                '(case-sensitive).';

            throw new InvalidConnectionChainItemException($message);
        }

        if ($host !== null && !$this->checkHost($host)) {
            throw new InvalidConnectionChainItemException("\"$host\" is not a valid host.");
        }

        if ($port !== null && !$this->checkPort($port)) {
            $portMin = self::PORT_MIN;
            $portMax = self::PORT_MAX;
            $message = "\"$port\" is not a valid port. Port must be a number between $portMin and $portMax.";

            throw new InvalidConnectionChainItemException($message);
        }

        /**
         * @psalm-var ?non-empty-string $ip
         * @psalm-var ?TrustedHostsNetworkResolver::PROTOCOL_* $protocol
         * @psalm-var ?non-empty-string $host
         * @psalm-var ?string $port
         * @psalm-var ?non-empty-string $ipIdentifier
         */
        return [
            'ip' => $ip,
            'protocol' => $protocol,
            'host' => $host,
            'port' => $port !== null ? (int) $port : $port,
            'ipIdentifier' => $ipIdentifier,
        ];
    }

    /**
     * @psalm-param list<RawConnectionChainItem> $items
     * @psalm-param list<ConnectionChainItem> $validatedItems
     * @psalm-param-out list<ConnectionChainItem> $validatedItems
     *
     * @psalm-return ConnectionChainItem
     */
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
            if ($rawItem['ipIdentifier'] !== null) {
                if ($rawItem['ipIdentifier'] === 'unknown') {
                    break;
                }

                $ipData = $this->reverseObfuscateIpIdentifier(
                    $rawItem['ipIdentifier'],
                    $validatedItems,
                    $remainingItems,
                    $request,
                );
                $this->assertReverseObfuscatedIpData($ipData);
                if ($ipData !== null) {
                    $rawItem['ip'] = $ipData[0];

                    if ($ipData[1] !== null) {
                        $rawItem['port'] = $ipData[1];
                    }
                }
            }

            $ip = $rawItem['ip'];
            if ($ip === null) {
                break;
            }

            /** @psalm-var ConnectionChainItem $rawItem */

            if ($proxiesCount >= 3) {
                $item = $rawItem;
            }

            if (!$this->checkTrustedIp($ip)) {
                break;
            }

            $item = $rawItem;
            $validatedItems[] = $item;
        } while (count($remainingItems) > 0);

        return $item;
    }

    /**
     * @psalm-assert ?array{0: non-empty-string, 1: ?non-empty-string} $ipData
     */
    private function assertReverseObfuscatedIpData(?array $ipData): void
    {
        if ($ipData === null) {
            return;
        }

        $this->assertNonEmpty($ipData, 'Reverse-obfuscated IP data', inRuntime: true);
        $this->assertExactKeysForArray([0, 1], $ipData, 'reverse-obfuscated IP data', inRuntime: true);
        $this->assertIsNonEmptyString($ipData[0], 'IP returned from reverse-obfuscated IP data', inRuntime: true);

        if (!$this->checkIp($ipData[0])) {
            throw new RuntimeException('IP returned from reverse-obfuscated IP data is not valid.');
        }

        if ($ipData[1] === null) {
            return;
        }

        $this->assertIsNonEmptyString($ipData[1], 'Port returned from reverse-obfuscated IP data', inRuntime: true);

        if (!$this->checkPort($ipData[1])) {
            throw new RuntimeException('Port returned from reverse-obfuscated IP data is not valid.');
        }
    }

    /**
     * @psalm-assert non-empty-string $value
     */
    private function checkIp(string $value): bool
    {
        return $this
            ->validator
            ->validate($value, [new Ip()])
            ->isValid();
    }

    /**
     * @psalm-assert non-empty-string $value
     */
    private function checkIpv6(string $value): bool
    {
        return $this
            ->validator
            ->validate($value, [new Ip(allowIpv4: false)])
            ->isValid();
    }

    /**
     * @psalm-param non-empty-string $value
     */
    private function checkTrustedIp(string $value): bool
    {
        return (new Ip(ranges: $this->trustedIps))->isAllowed($value);
    }

    /**
     * @psalm-assert TrustedHostsNetworkResolver::PROTOCOL_* $value
     */
    private function checkProtocol(string $value): bool
    {
        return in_array($value, self::ALLOWED_PROTOCOLS);
    }

    /**
     * @psalm-assert non-empty-string $value
     */
    private function checkHost(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }

    /**
     * @psalm-assert non-empty-string $value
     */
    private function checkPort(string $value): bool
    {
        /**
         * @infection-ignore-all
         * - PregMatchRemoveCaret.
         * - PregMatchRemoveDollar.
         */
        if (preg_match('/^\d{1,5}$/', $value) !== 1) {
            return false;
        }

        /** @infection-ignore-all CastInt */
        $intValue = (int) $value;

        return $intValue >= self::PORT_MIN && $intValue <= self::PORT_MAX;
    }

    /**
     * @psalm-assert non-empty-string $value
     */
    private function checkIpIdentifier(string $value): bool
    {
        return $value === 'unknown' || preg_match('/_[\w.-]+$/', $value) !== 0;
    }
}

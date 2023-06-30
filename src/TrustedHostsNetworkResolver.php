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

use function count;
use function in_array;
use function is_array;
use function is_callable;
use function is_string;

/**
 * Scans the entire connection chain and resolves the data from forwarded headers taking into account trusted IPs.
 * Additionally, all items' structure is thoroughly validated because headers' data can't be trusted. The following data
 * is resolved:
 *
 * - IP.
 * - Protocol.
 * - Host.
 * - Port.
 * - IP identifier - [unknown](https://datatracker.ietf.org/doc/html/rfc7239#section-6.2) or
 * [obfuscated](https://datatracker.ietf.org/doc/html/rfc7239#section-6.3). Used with `Forwarded` RFC header.
 *
 * The typical use case is having an application behind a load balancer.
 *
 * @psalm-type ProtocolResolvingMapping = array<non-empty-string, TrustedHostsNetworkResolver::PROTOCOL_*>
 * @psalm-type ProtocolResolvingCallable = Closure(non-empty-string): ?non-empty-string
 * @psalm-type ProtocolConfig = lowercase-string | array{0: lowercase-string, 1: ProtocolResolvingMapping | ProtocolResolvingCallable}
 * @psalm-type SeparateForwardedHeaderGroup = array{
 *     ip: lowercase-string,
 *     protocol: ProtocolConfig,
 *     host: lowercase-string,
 *     port: lowercase-string,
 * }
 * @psalm-type ForwardedHeaderGroup = TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC | SeparateForwardedHeaderGroup
 * @psalm-type ForwardedHeaderGroups = non-empty-list<ForwardedHeaderGroup>
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
    /**
     * The name of forwarded header according to RFC 7239.
     *
     * @link https://datatracker.ietf.org/doc/html/rfc7239#section-4
     */
    public const FORWARDED_HEADER_RFC = 'forwarded';
    /**
     * The forwarded header group containing forwarded header according to RFC 7239 for including in
     * {@see $forwardedHeaderGroups}. In this case the group contains only 1 header with all the data -
     * {@see FORWARDED_HEADER_RFC}.
     *
     * @link https://datatracker.ietf.org/doc/html/rfc7239#section-4
     */
    public const FORWARDED_HEADER_GROUP_RFC = self::FORWARDED_HEADER_RFC;
    /**
     * The forwarded header group containing headers with "X" prefix for including in {@see $forwardedHeaderGroups}. In
     * this case, the group contains multiple headers and the data is passed separately among them.
     */
    public const FORWARDED_HEADER_GROUP_X_PREFIX = [
        'ip' => 'x-forwarded-for',
        'protocol' => 'x-forwarded-proto',
        'host' => 'x-forwarded-host',
        'port' => 'x-forwarded-port',
    ];
    /**
     * Default value for {@see $forwardedHeaderGroups}.
     */
    public const DEFAULT_FORWARDED_HEADER_GROUPS = [
        self::FORWARDED_HEADER_GROUP_RFC,
        self::FORWARDED_HEADER_GROUP_X_PREFIX,
    ];
    /**
     * Default value for {@see $typicalForwardedHeaders}.
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
     * The name of request's attribute for storing resolved connection chain item's IP.
     */
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
    private array $trustedIps = [];
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

    /**
     * Returns a new instance with changed list of connection chain trusted IPs
     *
     * @param array $trustedIps List of connection chain trusted IPs.
     * @return self New instance.
     *
     * @throws InvalidArgumentException When list contains invalid IPs.
     * @see https://github.com/yiisoft/proxy-middleware#trusted-ips For detailed explanation and example.
     */
    public function withTrustedIps(array $trustedIps): self
    {
        $validatedIps = [];
        foreach ($trustedIps as $ip) {
            $this->assertIsNonEmptyString($ip, 'Trusted IP');

            if (!$this->isIp($ip)) {
                throw new InvalidArgumentException("\"$ip\" is not a valid IP.");
            }

            $validatedIps[] = $ip;
        }

        $new = clone $this;
        $new->trustedIps = $validatedIps;

        return $new;
    }

    /**
     * Returns a new instance with changed list of forwarded header groups to parse the data from. By including headers
     * in this list, they are trusted automatically.
     *
     * The header groups are processed in the order they are defined. If the header containing IP is present and is
     * non-empty, this group will be selected and further ones will be ignored.
     *
     * @param array $headerGroups List of forwarded header groups.
     * @return self New instance.
     *
     * @throws InvalidArgumentException When the structure/contents of header groups is incorrect.
     * @see https://github.com/yiisoft/proxy-middleware#forwarded-header-groups For detailed explanation and examples.
     */
    public function withForwardedHeaderGroups(array $headerGroups): self
    {
        $this->assertNonEmpty($headerGroups, 'Forwarded header groups');

        /** @psalm-var non-empty-array $headerGroups */

        $allowedHeaderGroupKeys = ['ip', 'protocol', 'host', 'port'];
        $validatedHeaderGroups = [];
        foreach ($headerGroups as $headerGroup) {
            if ($headerGroup === self::FORWARDED_HEADER_GROUP_RFC) {
                $validatedHeaderGroups[] = $headerGroup;
            } elseif (is_array($headerGroup)) {
                $this->assertNonEmpty($headerGroup, 'Forwarded header group array');
                $this->assertExactKeysForArray($allowedHeaderGroupKeys, $headerGroup, 'forwarded header group');

                $validatedHeaderGroup = [];
                foreach (['ip', 'host', 'port'] as $key) {
                    $this->assertIsNonEmptyString($headerGroup[$key], "Header name for \"$key\"");
                    $validatedHeaderGroup[$key] = $this->normalizeHeaderName($headerGroup[$key]);
                }

                if (is_string($headerGroup['protocol'])) {
                    $this->assertNonEmpty($headerGroup['protocol'], 'Header name for "protocol"');
                    $validatedHeaderGroup['protocol'] = $this->normalizeHeaderName($headerGroup['protocol']);
                } elseif (is_array($headerGroup['protocol'])) {
                    $this->assertNonEmpty($headerGroup['protocol'], 'Protocol header config array');
                    $this->assertExactKeysForArray([0, 1], $headerGroup['protocol'], 'protocol header config');
                    $this->assertIsNonEmptyString($headerGroup['protocol'][0], 'Header name for "protocol"');
                    $headerName = $this->normalizeHeaderName($headerGroup['protocol'][0]);

                    if (is_array($headerGroup['protocol'][1])) {
                        $this->assertNonEmpty($headerGroup['protocol'][1], 'Values in mapping for protocol header');

                        foreach ($headerGroup['protocol'][1] as $key => $value) {
                            $this->assertIsNonEmptyString($key, 'Key in mapping for protocol header');
                            $this->assertIsAllowedProtocol($value, 'Value in mapping for protocol header');
                        }
                    } elseif (!is_callable($headerGroup['protocol'][1])) {
                        $message = 'Protocol header resolving must be specified either via an associative array or a ' .
                            'callable.';

                        throw new InvalidArgumentException($message);
                    }

                    $validatedHeaderGroup['protocol'] = [$headerName, $headerGroup['protocol'][1]];
                } else {
                    throw new InvalidArgumentException('Protocol header config must be either a string or an array.');
                }

                /** @psalm-var SeparateForwardedHeaderGroup $validatedHeaderGroup */

                $validatedHeaderGroups[] = $validatedHeaderGroup;
            } else {
                $message = 'Forwarded header group must be either an associative array or ' .
                    'TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC constant.';

                throw new InvalidArgumentException($message);
            }
        }

        $new = clone $this;
        $new->forwardedHeaderGroups = $validatedHeaderGroups;
        return $new;
    }

    /**
     * Returns a new instance with changed list of headers that are considered related to forwarding.
     *
     * The headers that are present in this list but missing in a matching forwarded header group will be deleted from
     * request because they are potentially not secure and likely were not passed by a proxy server.
     *
     * @param array $headerNames List of headers that are considered related to forwarding. Header names are
     * case-insensitive.
     * @return self New instance.
     *
     * @throws InvalidArgumentException When list is empty or header within it is empty.
     * @see https://github.com/yiisoft/proxy-middleware#typical-forwarded-headers For example.
     */
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

    /**
     * Returns a new instance with changed name of request's attribute for storing validated and trusted connection
     * chain items.
     *
     * @param string|null $attribute The name of request's attribute. Can be set to `null` to disable saving completely.
     * @return self New instance.
     *
     * @throws InvalidArgumentException When attribute name is empty.
     * @see https://github.com/yiisoft/proxy-middleware#accessing-resolved-data For example.
     */
    public function withConnectionChainItemsAttribute(?string $attribute): self
    {
        if (is_string($attribute)) {
            $this->assertNonEmpty($attribute, 'Attribute');
        }

        /** @var ?non-empty-string $attribute */

        $new = clone $this;
        $new->connectionChainItemsAttribute = $attribute;
        return $new;
    }

    /**
     * @inheritdoc
     *
     * @throws RuntimeException When value returned from protocol resolving callable in {@see $forwardedHeaderGroups} or
     * overridden {@see reverseObfuscateIpIdentifier} method is incorrect.
     * @throws RfcProxyParseException When parsing of {@see FORWARDED_HEADER_RFC} failed.
     * @throws InvalidConnectionChainItemException When resolved data of connection chain item (IP, protocol, host or
     * port) is invalid.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /** @var string|null $remoteAddr */
        $remoteAddr = $request->getServerParams()['REMOTE_ADDR'] ?? null;
        if (empty($remoteAddr)) {
            return $this->handleNotTrusted($request, $handler);
        }

        [$forwardedHeaderGroup, $connectionChainItems] = $this->getConnectionChainItems($remoteAddr, $request);
        $request = $this->filterTypicalForwardedHeaders($forwardedHeaderGroup, $request);

        $validatedConnectionChainItems = [];
        $connectionChainItem = $this->iterateConnectionChainItems(
            $connectionChainItems,
            $validatedConnectionChainItems,
            $request,
        );

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
     * A method intended to be overridden in user class for resolving obfuscated IP identifier obtained from
     * {@see FORWARDED_HEADER_RFC}.
     *
     * @param string $ipIdentifier Obfuscated IP identifier.
     * @psalm-param non-empty-string $ipIdentifier
     *
     * @param array $validatedConnectionChainItems Connection chain items that are already trusted and passed the
     * validation.
     * @psalm-param list<ConnectionChainItem> $validatedConnectionChainItems
     *
     * @param array $remainingConnectionChainItems Connection chain items that are left to check whether they are valid
     * and can be trusted.
     * @psalm-param list<RawConnectionChainItem> $remainingConnectionChainItems
     *
     * @return ?array A list with 2 items where:
     *
     * - 1st item is expected to be IP;
     * - 2nd item is expected to be port (or `null` when there is no port).
     *
     * When unable to resolve IP identifier, `null` must be returned.
     *
     * @link https://tools.ietf.org/html/rfc7239#section-6.3
     * @see https://github.com/yiisoft/proxy-middleware#reverse-obfuscating-ip-identifier For example.
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

        $exceptionClassName = $inRuntime ? RuntimeException::class : InvalidArgumentException::class;

        throw new $exceptionClassName("$name can't be empty.");
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
        $exceptionClassName = $inRuntime ? RuntimeException::class : InvalidArgumentException::class;

        throw new $exceptionClassName($message);
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

        $exceptionClassName = $inRuntime ? RuntimeException::class : InvalidArgumentException::class;

        throw new $exceptionClassName("$name must be non-empty string.");
    }

    /**
     * @psalm-assert TrustedHostsNetworkResolver::PROTOCOL_* $value
     * @psalm-param non-empty-string $name
     */
    private function assertIsAllowedProtocol(mixed $value, string $name, bool $inRuntime = false): void
    {
        $this->assertIsNonEmptyString($value, $name);

        if ($this->isProtocol($value)) {
            return;
        }

        $allowedProtocolsStr = implode('", "', self::ALLOWED_PROTOCOLS);
        $message = "$name must be a valid protocol. Allowed values are: \"$allowedProtocolsStr\" (case-sensitive).";
        $exceptionClassName = $inRuntime ? RuntimeException::class : InvalidArgumentException::class;

        throw new $exceptionClassName($message);
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
     * @psalm-param ForwardedHeaderGroup $forwardedHeaderGroup
     */
    private function filterTypicalForwardedHeaders(
        string|array $forwardedHeaderGroup,
        ServerRequestInterface $request,
    ): ServerRequestInterface
    {
        $forwardedHeaders = $this->getForwardedHeadersFromGroup($forwardedHeaderGroup);
        $headers = array_diff($this->typicalForwardedHeaders, $forwardedHeaders);
        foreach ($headers as $header) {
            $request = $request->withoutHeader($header);
        }

        return $request;
    }

    /**
     * @psalm-param ForwardedHeaderGroup $group
     *
     * @psalm-return list<lowercase-string>
     */
    private function getForwardedHeadersFromGroup(string|array $group): array
    {
        $headers = [];

        if (is_string($group)) {
            $headers[] = $group;
        } else {
            $headers[] = $group['ip'];
            $headers[] = is_string($group['protocol']) ? $group['protocol'] : $group['protocol'][0];
            $headers[] = $group['host'];
            $headers[] = $group['port'];
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
     * @psalm-return array{0: ForwardedHeaderGroup, 1: list<RawConnectionChainItem>}
     *
     * @throws InvalidConnectionChainItemException
     * @throws RfcProxyParseException
     */
    private function getConnectionChainItems(string $remoteAddr, ServerRequestInterface $request): array
    {
        /** @infection-ignore-all FalseValue */
        $items = [$this->getConnectionChainItem(ip: $remoteAddr, validateIp: false)];
        foreach ($this->forwardedHeaderGroups as $forwardedHeaderGroup) {
            if ($forwardedHeaderGroup === self::FORWARDED_HEADER_GROUP_RFC) {
                /** @psalm-var list<string> $forwardedHeaderValue */
                $forwardedHeaderValue = $request->getHeader(self::FORWARDED_HEADER_RFC);
                if (empty($forwardedHeaderValue) || empty($request->getHeaderLine(self::FORWARDED_HEADER_RFC))) {
                    continue;
                }

                $items = [$items[0], ...array_reverse($this->parseProxiesFromRfcHeader($forwardedHeaderValue))];

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

        return [$forwardedHeaderGroup, $items];
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

        return $protocol;
    }

    /**
     * @psalm-param list<string> $proxyItems
     *
     * @psalm-return list<RawConnectionChainItem>
     *
     * @link https://tools.ietf.org/html/rfc7239
     *
     * @throws RfcProxyParseException
     * @throws InvalidConnectionChainItemException
     */
    private function parseProxiesFromRfcHeader(array $proxyItems): array
    {
        $forPattern = '/^(?:(?<ipv4>[^:\[\]]+)|(?:\[(?<ipv6>.+)]))(?::(?<port>\d{1,5}+))?$/';
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

            $host = $directiveMap['host'] ?? null;
            $port = null;
            if ($host !== null) {
                /** @infection-ignore-all IncrementInteger */
                $hostParts = explode(':', $host, 2);
                $host = $hostParts[0];

                if (isset($hostParts[1])) {
                    $port = $hostParts[1];
                }
            }

            $wasIpValidated = false;

            if ($this->isIpIdentifier($directiveMap['for'])) {
                $ip = null;
                $ipIdentifier = $directiveMap['for'];
            } else {
                if (preg_match($forPattern, $directiveMap['for'], $matches) === 0) {
                    $message = 'Contents of "for" directive is invalid.';

                    throw new RfcProxyParseException($message);
                }

                if (isset($matches['ipv6']) && !empty($matches['ipv6'])) {
                    $ip = $matches['ipv6'];

                    if (!$this->isIpv6($ip)) {
                        $message = "Enclosing in square brackets assumes presence of valid IPv6, \"$ip\" given.";

                        throw new RfcProxyParseException($message);
                    }

                    /** @infection-ignore-all TrueValue */
                    $wasIpValidated = true;
                } else {
                    $ip = $matches['ipv4'];

                    if ($ip === '') {
                        throw new RfcProxyParseException('IP is missing in "for" directive.');
                    }
                }

                if ($port === null && isset($matches['port'])) {
                    $port = $matches['port'];
                }

                $ipIdentifier = null;
            }

            $proxies[] = $this->getConnectionChainItem(
                ip: $ip,
                protocol: $directiveMap['proto'] ?? null,
                host: $host,
                port: $port,
                ipIdentifier: $ipIdentifier,
                validateIp: !$wasIpValidated,
            );
        }

        return $proxies;
    }

    /**
     * @psalm-return RawConnectionChainItem
     *
     * @throws InvalidConnectionChainItemException
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
        if ($ip !== null && $validateIp && !$this->isIp($ip)) {
            throw new InvalidConnectionChainItemException("\"$ip\" is not a valid IP.");
        }

        if ($protocol !== null && $validateProtocol && !$this->isProtocol($protocol)) {
            $allowedProtocolsStr = implode('", "', self::ALLOWED_PROTOCOLS);
            $message = "\"$protocol\" protocol is not allowed. Allowed values are: \"$allowedProtocolsStr\" " .
                '(case-sensitive).';

            throw new InvalidConnectionChainItemException($message);
        }

        if ($host !== null && !$this->isHost($host)) {
            throw new InvalidConnectionChainItemException("\"$host\" is not a valid host.");
        }

        if ($port !== null && !$this->isPort($port)) {
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
    ): array
    {
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
                    $rawItem['port'] = $ipData[1];
                }
            }

            $ip = $rawItem['ip'];
            if ($ip === null) {
                break;
            }

            /** @infection-ignore-all  GreaterThan */
            if ($proxiesCount > 1 && $this->isPrivateIp($ip)) {
                break;
            }

            /** @psalm-var ConnectionChainItem $rawItem */

            $item = $rawItem;

            $isIpTrusted = $this->isTrustedIp($ip);
            if ($proxiesCount === 1 || $isIpTrusted) {
                $validatedItems[] = $item;
            }

            if (!$isIpTrusted) {
                break;
            }
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

        if ($ipData[1] !== null) {
            $this->assertIsNonEmptyString($ipData[1], 'Port returned from reverse-obfuscated IP data', inRuntime: true);

            if (!$this->isPort($ipData[1])) {
                throw new RuntimeException('Port returned from reverse-obfuscated IP data is not valid.');
            }
        }

        if (!$this->isIp($ipData[0])) {
            throw new RuntimeException('IP returned from reverse-obfuscated IP data is not valid.');
        }
    }

    /**
     * @psalm-assert non-empty-string $value
     */
    private function isIp(string $value): bool
    {
        return $this
            ->validator
            ->validate($value, [new Ip()])
            ->isValid();
    }

    /**
     * @psalm-assert non-empty-string $value
     */
    private function isIpv6(string $value): bool
    {
        return $this
            ->validator
            ->validate($value, [new Ip(allowIpv4: false)])
            ->isValid();
    }

    /**
     * @psalm-param non-empty-string $value
     */
    private function isPrivateIp(string $value): bool
    {
        return (new Ip(ranges: ['private']))->isAllowed($value);
    }

    /**
     * @psalm-param non-empty-string $value
     */
    private function isTrustedIp(string $value): bool
    {
        return !empty($this->trustedIps) && (new Ip(ranges: $this->trustedIps))->isAllowed($value);
    }

    /**
     * @psalm-assert TrustedHostsNetworkResolver::PROTOCOL_* $value
     */
    private function isProtocol(string $value): bool
    {
        return in_array($value, self::ALLOWED_PROTOCOLS);
    }

    /**
     * @psalm-assert non-empty-string $value
     */
    private function isHost(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }

    /**
     * @psalm-assert non-empty-string $value
     */
    private function isPort(string $value): bool
    {
        return $value >= self::PORT_MIN && $value <= self::PORT_MAX;
    }

    /**
     * @psalm-assert non-empty-string $value
     */
    private function isIpIdentifier(string $value): bool
    {
        return $value === 'unknown' || preg_match('/^_[\w.-]+$/', $value) !== 0;
    }
}

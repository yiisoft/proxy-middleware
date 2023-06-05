<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware;

use Closure;
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
use Yiisoft\ProxyMiddleware\Exception\InvalidProxyDataException;
use Yiisoft\ProxyMiddleware\Exception\InvalidRfcProxyItemException;
use Yiisoft\Validator\Rule\Ip;
use Yiisoft\Validator\ValidatorInterface;

use function array_reverse;
use function array_shift;
use function count;
use function filter_var;
use function is_array;
use function is_callable;
use function is_string;
use function preg_match;
use function str_starts_with;
use function strtolower;
use function trim;

/**
 * Trusted hosts network resolver can set IP, protocol, host, URL, and port based on trusted headers such as
 * `Forward` or `X-Forwarded-Host` coming from trusted hosts you define. Usually these are load balancers.
 *
 * Make sure that the trusted host always overwrites or removes user-defined headers
 * to avoid security issues.
 *
 * ```php
 * $trustedHostsNetworkResolver->withAddedTrustedHosts(
 *     // List of secure hosts including "$_SERVER['REMOTE_ADDR']".
 *     hosts: ['1.1.1.1', '2.2.2.1/3', '2001::/32', 'localhost'].
 *     // IP list headers.
 *     // Headers containing multiple sub-elements (e.g. RFC 7239) must also be listed for other relevant types
 *     // (such as host headers), otherwise they will only be used as an IP list.
 *     ipHeaders: ['x-forwarded-for', [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']]
 *     // Protocol headers with accepted protocols and corresponding header values. Matching is case-insensitive.
 *     protocolHeaders: ['front-end-https' => ['https' => 'on']],
 *     // List of headers containing HTTP host.
 *     hostHeaders: ['forwarded', 'x-forwarded-for']
 *     // List of headers containing HTTP URL.
 *     urlHeaders: ['x-rewrite-url'],
 *     // List of headers containing port number.
 *     portHeaders: ['x-rewrite-port'],
 *     // List of trusted headers. For untrusted hosts, middleware removes these from the request.
 *     trustedHeaders: ['x-forwarded-for', 'forwarded', ...],
 * );
 * ```
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
    /**
     * Name of the request attribute holding IP address obtained from a trusted header.
     */
    public const ATTRIBUTE_REQUEST_CLIENT_IP = 'requestClientIp';
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

    private array $typicalForwardedHeaders = self::TYPICAL_FORWARDED_HEADERS;
    private array $trustedHosts = [];
    private array $forwardedHeaderGroups = self::DEFAULT_FORWARDED_HEADER_GROUPS;

    private ?string $ipsAttribute = null;

    public function __construct(private ValidatorInterface $validator)
    {
    }

    /**
     * Returns a new instance with the added trusted hosts and related headers.
     *
     * The header lists are evaluated in the order they were specified.
     *
     * Make sure that the trusted host always overwrites or removes user-defined headers
     * to avoid security issues.
     *
     * @param string[] $hosts List of trusted host IP addresses. The {@see checkIp()} method could be overwritten in
     * a subclass to allow using domain names with reverse DNS resolving, for example `yiiframework.com`,
     * `*.yiiframework.com`. You can specify IPv4, IPv6, domains, and aliases. See {@see Ip}.
     * @param array $ipHeaders List of headers containing IP. For advanced handling of headers see
     * {@see TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239}.
     * @param array $protocolHeaders List of headers containing protocol. e.g.
     * `['x-forwarded-for' => ['http' => 'http', 'https' => ['on', 'https']]]`.
     * @param string[] $hostHeaders List of headers containing HTTP host.
     * @param string[] $urlHeaders List of headers containing HTTP URL.
     * @param string[] $portHeaders List of headers containing port number.
     * @param string[]|null $trustedHeaders List of trusted headers. For untrusted hosts, middleware removes these from
     * the request.
     */
    public function withTrustedHosts(array $trustedHosts): self {
        if (empty($trustedHosts)) {
            throw new InvalidArgumentException('Empty trusted hosts are not allowed.');
        }

        // TODO: Use one loop.
        $this->requireListOfNonEmptyStrings($trustedHosts, 'trusted hosts');

        foreach ($trustedHosts as $host) {
            if (!$this->checkIp($host)) {
                throw new InvalidArgumentException("\"$host\" host must be a valid IP address.");
            }
        }

        $new = clone $this;
        $new->trustedHosts = $trustedHosts;

        return $new;
    }

    public function withForwardedHeaderGroups(array $headerGroups): self
    {
        // TODO: Validate forwarded header groups.
        $new = clone $this;
        $new->forwardedHeaderGroups = $headerGroups;
        return $new;
    }

    public function withTypicalForwardedHeaders(array $headerNames): self
    {
        $new = clone $this;
        $new->typicalForwardedHeaders = $headerNames;
        return $new;
    }

    /**
     * Returns a new instance with the specified request's attribute name to which middleware writes trusted path data.
     *
     * @param string|null $attribute The request attribute name.
     *
     * @see parseProxiesFromRfcHeader()
     */
    public function withIpsAttribute(?string $attribute): self
    {
        if ($attribute === '') {
            throw new RuntimeException('Attribute should not be empty string.');
        }

        $new = clone $this;
        $new->ipsAttribute = $attribute;
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

        if ($this->ipsAttribute !== null) {
            $request = $request->withAttribute($this->ipsAttribute, $validatedConnectionChainItems);
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

    private function handleNotTrusted(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        if ($this->ipsAttribute !== null) {
            $request = $request->withAttribute($this->ipsAttribute, null);
        }

        return $handler->handle($request->withAttribute(self::ATTRIBUTE_REQUEST_CLIENT_IP, null));
    }

    /**
     * @psalm-return ProtocolHeadersData
     */
    private function prepareProtocolHeaders(array $protocolHeaders): array
    {
        $output = [];

        foreach ($protocolHeaders as $header => $protocolAndAcceptedValues) {
            if (!is_string($header)) {
                throw new InvalidArgumentException('The protocol header array key must be a string.');
            }

            $header = strtolower($header);

            if (is_callable($protocolAndAcceptedValues)) {
                $protocolAndAcceptedValues = $protocolAndAcceptedValues();
            }

            if (!is_array($protocolAndAcceptedValues)) {
                throw new InvalidArgumentException(
                    'Accepted values for protocol headers must be either an array or a callable returning array.',
                );
            }

            if (empty($protocolAndAcceptedValues)) {
                throw new InvalidArgumentException('Accepted values for protocol headers cannot be an empty array.');
            }

            $output[$header] = [];

            /** @psalm-var array<string|string[]> $protocolAndAcceptedValues */
            foreach ($protocolAndAcceptedValues as $protocol => $acceptedValues) {
                if (!is_string($protocol)) {
                    throw new InvalidArgumentException('The protocol must be a string.');
                }

                if ($protocol === '') {
                    throw new InvalidArgumentException('The protocol must be non-empty string.');
                }

                $output[$header][$protocol] = (array) $acceptedValues;
            }
        }

        return $output;
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
                    $rawItem['ip'] = null;
                }
            }

            if ($rawItem['hiddenPort'] !== null) {
                $ip = $this->reverseObfuscatePort($rawItem['hiddenPort'], $validatedItems, $remainingItems, $request);
                if ($ip !== null) {
                    $rawItem['ip'] = null;
                }
            }

            $ip = $rawItem['ip'];
            if (!$this->checkIp($ip)) {
                throw new InvalidProxyDataException("\"$ip\" is not a valid IP address.");
            }

            $protocol = $rawItem['protocol'];
            if ($protocol !== null && !$this->checkProtocol($protocol)) {
                throw new InvalidProxyDataException("\"$protocol\" is not a valid protocol.");
            }

            $port = $rawItem['port'];
            if ($port !== null) {
                if (!$this->checkPort($port)) {
                    throw new InvalidProxyDataException("\"$port\" is not a valid port.");
                }

                $rawItem['port'] = (int) $port;
            }

            if ($proxiesCount >= 3) {
                $item = $rawItem;
            }

            if (!$this->checkIp($ip, $this->trustedHosts)) {
                break;
            }

            $item = $rawItem;
            $validatedItems[] = $item;
        } while (count($remainingItems) > 0);

        return $item;
    }

    private function checkProtocol(string $scheme): bool
    {
        return in_array($scheme, ['http', 'https']);
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

    /**
     * @psalm-assert array<non-empty-string> $array
     */
    private function requireListOfNonEmptyStrings(array $array, string $arrayName): void
    {
        foreach ($array as $item) {
            if (!is_string($item)) {
                throw new InvalidArgumentException("Each \"$arrayName\" item must be string.");
            }

            if (trim($item) === '') {
                throw new InvalidArgumentException("Each \"$arrayName\" item must be non-empty string.");
            }
        }
    }

    private function getProtocol(ServerRequestInterface $request, string|array $configValue): ?string
    {
        if (is_string($configValue)) {
            return $request->getHeaderLine($configValue) ?: null;
        }

        $headerName = $configValue[0];
        $protocol = $request->getHeaderLine($headerName);
        if ($protocol === '') {
            return null;
        }

        // TODO: Support case-insensitive mapping?
        $protocol = $configValue[1][$protocol] ?? null;
        if ($protocol === null) {
            // TODO: Make exception message more helpful.
            throw new RuntimeException('Unable to resolve protocol via mapping.');
        }

        return $protocol;
    }
}

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
use Yiisoft\Validator\Result;
use Yiisoft\Validator\Rule\Ip;
use Yiisoft\Validator\ValidatorInterface;

use function array_diff;
use function array_reverse;
use function array_shift;
use function array_unshift;
use function count;
use function explode;
use function filter_var;
use function in_array;
use function is_array;
use function is_callable;
use function is_string;
use function preg_match;
use function str_replace;
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
 * @psalm-type HostData = array{ip?:string, host?: string, by?: string, port?: string|int, protocol?: string, httpHost?: string}
 * @psalm-type ProtocolHeadersData = array<string, array<non-empty-string, array<array-key, string>>|callable>
 * @psalm-type TrustedHostData = array{
 *     'hosts': array<array-key, string>,
 *     'ipHeaders': array<array-key, string>,
 *     'protocolHeaders': ProtocolHeadersData,
 *     'hostHeaders': array<array-key, string>,
 *     'portHeaders': array<array-key, string>,
 *     'trustedHeaders': array<array-key, string>
 * }
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
     * @param string[] $hosts List of trusted host IP addresses. The {@see isValidHost()} method could be overwritten in
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
            /**
             * Wildcard is allowed in host. It's replaced by placeholder temporarily just for validation, because it's
             * not supported by {@see filter_var}.
             */
            $host = str_replace('*', 'wildcard', $host);

            if (filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
                throw new InvalidArgumentException("\"$host\" host must be either a domain or an IP address.");
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
     * @see getElementsByRfc7239()
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
        /** @var string|null $remoteAddr */
        $remoteAddr = $request->getServerParams()['REMOTE_ADDR'] ?? null;
        if ($remoteAddr === null) {
            return $this->handleNotTrusted($request, $handler);
        }

        // TODO: Remove non-typical forwarded headers.
        // TODO: Handle "by".

        // TODO: Should default value be used for protocol ("http")?
        $proxies = [['ip' => $remoteAddr, 'protocol' => null, 'host' => null, 'port' => null]];
        foreach ($this->forwardedHeaderGroups as $forwardedHeaderGroup) {
            if ($forwardedHeaderGroup === self::FORWARDED_HEADER_GROUP_RFC) {
                if (!$request->hasHeader('forwarded')) {
                    continue;
                }

                // TODO: Handle empty forwarded list.

                $forwardedHeaderValue = $request->getHeader('forwarded');
                $proxies = [...$proxies, ...array_reverse($this->getElementsByRfc7239($forwardedHeaderValue))];

                break;
            }

            if (!$request->hasHeader($forwardedHeaderGroup['ip'])) {
                continue;
            }

            // TODO: Handle empty IP list.

            $proxies = [];
            $requestIps = array_merge([$remoteAddr], array_reverse($request->getHeader($forwardedHeaderGroup['ip'])));
            foreach ($requestIps as $requestIp) {
                // TODO: Add validation.
                $proxies[] = [
                    'ip' => $requestIp,
                    'protocol' => $this->getProtocol($request, $forwardedHeaderGroup['protocol']),
                    'host' => $request->getHeaderLine($forwardedHeaderGroup['host']) ?: null,
                    'port' => (int) $request->getHeaderLine($forwardedHeaderGroup['port']) ?: null,
                ];
            }

            break;
        }

        $proxy = null;
        $remainingProxies = $proxies;
        $validatedProxies = [];
        $proxiesCount = 0;

        do {
            $proxiesCount++;

            $rawProxy = array_shift($remainingProxies);

            // TODO: Handle reverse obfuscate.

            $ip = $rawProxy['ip'];
            if (!$this->isValidHost($ip)) {
                throw new RuntimeException("Proxy returned the invalid IP: \"$ip\". Check its configuration.");
            }

            if ($proxiesCount >= 3) {
                $proxy = $rawProxy;
            }

            if (!$this->isValidHost($ip, $this->trustedHosts)) {
                break;
            }

            $proxy = $rawProxy;
            $validatedProxies[] = $proxy;
        } while (count($remainingProxies) > 0);

        if ($proxy === null) {
            return $this->handleNotTrusted($request, $handler);
        }

        if ($this->ipsAttribute !== null) {
            $request = $request->withAttribute($this->ipsAttribute, $validatedProxies);
        }

        $uri = $request->getUri();

        $host = $proxy['host'] ?? null;
        if ($host !== null && filter_var($host, FILTER_VALIDATE_DOMAIN) !== false) {
            $uri = $uri->withHost($host);
        }

        $protocol = $proxy['protocol'] ?? null;
        if ($protocol !== null) {
            $uri = $uri->withScheme($protocol);
        }

        $port = $proxy['port'] ?? null;
        if ($port !== null && $this->checkPort((string) $port)) {
            $uri = $uri->withPort((int) $port);
        }

        $request = $request
            ->withUri($uri)
            ->withAttribute(self::ATTRIBUTE_REQUEST_CLIENT_IP, $proxy['ip']);

        return $handler->handle($request);
    }

    /**
     * Validate host by range.
     *
     * You can overwrite this method in a subclass to support reverse DNS verification.
     *
     * @param string[] $ranges
     * @psalm-param Closure(string, string[]): Result $validator
     */
    protected function isValidHost(string $host, array $ranges = []): bool
    {
        return $this
            ->validator
            ->validate($host, [new Ip(ranges: $ranges)])
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
     * @return array|null reverse obfuscated host data or null.
     * In case of `null` data is discarded, and the process continues with the next portion of host data.
     * If the return value is an array, it must contain at least the `ip` key.
     *
     * @psalm-param HostData|null $hostData
     *
     * @psalm-return HostData|null
     *
     * @see getElementsByRfc7239()
     * @link https://tools.ietf.org/html/rfc7239#section-6.2
     * @link https://tools.ietf.org/html/rfc7239#section-6.3
     */
    protected function reverseObfuscate(
        ?array $proxy,
        array $validatedProxies,
        array $remainingProxies,
        RequestInterface $request,
    ): ?array {
        return $proxy;
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
     * - `ip`: IP address (only if presented)
     * - `by`: used user-agent by proxy (only if presented)
     * - `port`: port number received by proxy (only if present)
     * - `protocol`: protocol received by proxy (only if present)
     * - `host`: HTTP host received by proxy (only if present)
     *
     * The list starts with the server, and the last item is the client itself.
     *
     * @link https://tools.ietf.org/html/rfc7239
     *
     * @param string[] $forwards
     *
     * @psalm-return list<HostData> Proxy data elements.
     */
    private function getElementsByRfc7239(array $forwards): array
    {
        $list = [];

        foreach ($forwards as $forward) {
            try {
                /** @psalm-var array<string, string> $data */
                $data = HeaderValueHelper::getParameters($forward);
            } catch (InvalidArgumentException) {
                break;
            }

            // TODO: Validate structure.

            if (!isset($data['for'])) {
                // Invalid item, the following items will be dropped.
                break;
            }

            // TODO: Should port be parsed from host instead?
            $pattern = '/^(?<host>' . IpHelper::IPV4_PATTERN . '|unknown|_[\w.-]+|[[]'
                . IpHelper::IPV6_PATTERN . '[]])(?::(?<port>[\w.-]+))?$/';

            if (preg_match($pattern, $data['for'], $matches) === 0) {
                // Invalid item, the following items will be dropped.
                break;
            }

            $ipData = [];
            $host = $matches['host'];
            $obfuscatedHost = $host === 'unknown' || str_starts_with($host, '_');

            if (!$obfuscatedHost) {
                // IPv4 & IPv6.
                $ipData['ip'] = str_starts_with($host, '[') ? trim($host /* IPv6 */, '[]') : $host;
            }

            $ipData['protocol'] = $data['proto'] ?? null;
            $ipData['host'] = $data['host'] ?? null;

            if (isset($ipData['host']) && filter_var($ipData['host'], FILTER_VALIDATE_DOMAIN) === false) {
                // Remove not valid HTTP host.
                unset($ipData['host']);
            }

            if (!isset($matches['port'])) {
                $ipData['port'] = null;
            } else {
                $port = $matches['port'];

                if (!$obfuscatedHost && !$this->checkPort($port)) {
                    // Invalid port, the following items will be dropped.
                    break;
                }

                $ipData['port'] = $obfuscatedHost ? $port : (int) $port;
            }

            $list[] = $ipData;
        }

        return $list;
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

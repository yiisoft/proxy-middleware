<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Exception;

use Exception;

/**
 * Used by {@see TrustedHostsNetworkResolver}. Thrown when parsing of {@see FORWARDED_HEADER_RFC} failed. Forwarded
 * header is expected to meet the requirements described in RFC 7239.
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7239
 */
final class RfcProxyParseException extends Exception
{
}

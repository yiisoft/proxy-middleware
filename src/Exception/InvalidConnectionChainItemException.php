<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Exception;

use Exception;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

/**
 * Used by {@see TrustedHostsNetworkResolver}. Thrown when resolved data of connection chain item - either IP, protocol,
 * host or port is invalid.
 */
final class InvalidConnectionChainItemException extends Exception
{
}

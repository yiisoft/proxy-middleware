<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware;

use Yiisoft\NetworkUtilities\IpHelper;
use Yiisoft\NetworkUtilities\IpRanges;

/**
 * @internal
 */
final class IpValidator
{
    public static function isIp(string $value): bool
    {
        return self::isIpV4($value) || self::isIpV6($value);
    }

    public static function isIpV6(string $value): bool
    {
        return preg_match(IpHelper::IPV6_REGEXP, $value) === 1;
    }

    /**
     * @param string[] $ranges
     */
    public static function inRanges(string $value, array $ranges): bool
    {
        return (new IpRanges($ranges))->isAllowed($value);
    }

    private static function isIpV4(string $value): bool
    {
        return preg_match(IpHelper::IPV4_REGEXP, $value) === 1;
    }
}

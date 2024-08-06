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
    public function isIp(string $value): bool
    {
        return $this->isIpV4($value) || $this->isIpV6($value);
    }

    public function isIpV4(string $value): bool
    {
        return preg_match(IpHelper::IPV4_REGEXP, $value) === 1;
    }

    public function isIpV6(string $value): bool
    {
        return preg_match(IpHelper::IPV6_REGEXP, $value) === 1;
    }

    /**
     * @param string[] $ranges
     */
    public function inRanges(string $value, array $ranges): bool
    {
        return (new IpRanges($ranges))->isAllowed($value);
    }
}

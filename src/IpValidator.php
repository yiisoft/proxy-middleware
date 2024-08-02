<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware;

use Yiisoft\NetworkUtilities\IpHelper;

/**
 * @internal
 */
final class IpValidator
{
    private const NETWORKS = [
        '*' => ['any'],
        'any' => ['0.0.0.0/0', '::/0'],
        'private' => ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fd00::/8'],
        'multicast' => ['224.0.0.0/4', 'ff00::/8'],
        'linklocal' => ['169.254.0.0/16', 'fe80::/10'],
        'localhost' => ['127.0.0.0/8', '::1'],
        'documentation' => ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'],
        'system' => ['multicast', 'linklocal', 'localhost', 'documentation'],
    ];

    private const IPV4_PATTERN = '((2(5[0-5]|[0-4]\d)|1\d{2}|[1-9]?\d)\.){3}(2(5[0-5]|[0-4]\d)|1\d{2}|[1-9]?\d)';
    private const IPV6_PATTERN = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:' . self::IPV4_PATTERN . ')';

    public function validate(string $value, bool $allowIpv4 = true): bool
    {
        if (preg_match('/^' . self::IPV4_PATTERN . '$/', $value) === 1) {
            $isIpV4 = true;
        } elseif (preg_match('/^' . self::IPV6_PATTERN . '$/', $value) === 1) {
            $isIpV4 = false;
        } else {
            return false;
        }

        if ($isIpV4 && !$allowIpv4) {
            return false;
        }

        return true;
    }

    /**
     * @param string[] $ranges
     */
    public function isAllowed(string $value, array $ranges): bool
    {
        $ranges = $this->prepareRanges($ranges);

        if (empty($ranges)) {
            return true;
        }

        foreach ($ranges as $string) {
            [$isNegated, $range] = $this->parseNegatedRange($string);
            if (IpHelper::inRange($value, $range)) {
                return !$isNegated;
            }
        }

        return false;
    }

    /**
     * Parses IP address/range for the negation with {@see NEGATION_CHARACTER}.
     *
     * @return array The result array consists of 2 elements:
     * - `boolean`: whether the string is negated
     * - `string`: the string without negation (when the negation were present)
     *
     * @psalm-return array{0: bool, 1: string}
     */
    private function parseNegatedRange(string $string): array
    {
        $isNegated = str_starts_with($string, '!');
        return [$isNegated, $isNegated ? substr($string, 1) : $string];
    }

    /**
     * Prepares array to fill in {@see $ranges}:
     *
     *  - Recursively substitutes aliases, described in {@see $networks} with their values.
     *  - Removes duplicates.
     *
     * @param string[] $ranges
     *
     * @return string[]
     */
    private function prepareRanges(array $ranges): array
    {
        $result = [];
        foreach ($ranges as $string) {
            [$isRangeNegated, $range] = $this->parseNegatedRange($string);
            if (isset(self::NETWORKS[$range])) {
                $replacements = $this->prepareRanges(self::NETWORKS[$range]);
                foreach ($replacements as &$replacement) {
                    [$isReplacementNegated, $replacement] = $this->parseNegatedRange($replacement);
                    $result[] = ($isRangeNegated && !$isReplacementNegated ? '!' : '') . $replacement;
                }
            } else {
                $result[] = $string;
            }
        }

        return array_unique($result);
    }
}

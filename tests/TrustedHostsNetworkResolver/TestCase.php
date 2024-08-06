<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Tests\TrustedHostsNetworkResolver;

use HttpSoft\Message\ServerRequest;
use PHPUnit\Framework\TestCase as PHPUnitTestCase;
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

class TestCase extends PHPUnitTestCase
{
    protected function createMiddleware(): TrustedHostsNetworkResolver
    {
        return new TrustedHostsNetworkResolver();
    }

    protected function createRequest(
        array $headers = [],
        array $serverParams = [],
        string $scheme = 'http',
    ): ServerRequestInterface {
        $request = new ServerRequest($serverParams);

        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        $uri = $request->getUri()->withScheme($scheme)->withPath('/');

        return $request->withUri($uri);
    }
}

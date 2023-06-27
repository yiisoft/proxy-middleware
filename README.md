<p align="center">
    <a href="https://github.com/yiisoft" target="_blank">
        <img src="https://yiisoft.github.io/docs/images/yii_logo.svg" height="100px">
    </a>
    <h1 align="center">Yii Proxy Middleware</h1>
    <br>
</p>

[![Latest Stable Version](https://poser.pugx.org/yiisoft/proxy-middleware/v/stable.png)](https://packagist.org/packages/yiisoft/proxy-middleware)
[![Total Downloads](https://poser.pugx.org/yiisoft/proxy-middleware/downloads.png)](https://packagist.org/packages/yiisoft/proxy-middleware)
[![Build status](https://github.com/yiisoft/proxy-middleware/workflows/build/badge.svg)](https://github.com/yiisoft/proxy-middleware/actions?query=workflow%3Abuild)
[![Code Coverage](https://codecov.io/gh/yiisoft/proxy-middleware/branch/master/graph/badge.svg)](https://codecov.io/gh/yiisoft/proxy-middleware)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fyiisoft%2Fproxy-middleware%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/yiisoft/proxy-middleware/master)
[![static analysis](https://github.com/yiisoft/proxy-middleware/workflows/static%20analysis/badge.svg)](https://github.com/yiisoft/proxy-middleware/actions?query=workflow%3A%22static+analysis%22)
[![type-coverage](https://shepherd.dev/github/yiisoft/proxy-middleware/coverage.svg)](https://shepherd.dev/github/yiisoft/proxy-middleware)
[![psalm-level](https://shepherd.dev/github/yiisoft/proxy-middleware/level.svg)](https://shepherd.dev/github/yiisoft/proxy-middleware)

The package ...

## Requirements

- PHP 8.1 or higher.

## Installation

The package could be installed with composer:

```shell
composer require yiisoft/proxy-middleware
```

## General usage

### `TrustedHeaderProtocolResolver`

Trusted header protocol resolver sets a server request protocol based on special header you trust
such as `X-Forwarded-Proto`.

You can use it if your server is behind a trusted load balancer or a proxy that's always setting the special header
itself discarding any header values provided by user.

```php
use Yiisoft\Yii\Middleware\TrustedHeaderProtocolResolver;

/**
 * @var Psr\Http\Message\ServerRequestInterface $request
 * @var Psr\Http\Server\RequestHandlerInterface $handler
 */

$middleware = new TrustedHeaderProtocolResolver();

$middleware = $middleware->withAddedProtocolHeader('x-forwarded-proto', [
    'http' => ['http'],
    'https' => ['https', 'on'],
]);
// Disable earlier settings:
$middleware = $middleware->withoutProtocolHeader('x-forwarded-proto');

$response = $middleware->process($request, $handler);
```

### `TrustedHostsNetworkResolver`

Scans the entire connection chain and resolves the data from forwarded headers taking into account trusted IPs.
Additionally, all items' structure is thoroughly validated because headers' data can't be trusted. The following data is 
resolved:

- IP.
- Protocol
- Host.
- Port.
- IP identifier - [unknown](https://datatracker.ietf.org/doc/html/rfc7239#section-6.2) or 
[obfuscated](https://datatracker.ietf.org/doc/html/rfc7239#section-6.3). Used with `Forwarded` RFC header. 

The typical use case is having an application behind a load balancer.

#### Trusted IPs

A list of trusted IPs from connection chain.

This is the only required setting, the rest are optional. Besides proxies' IPs, this list must include the IP of a 
client that passes through a proxy as well (can be retrieved using `$_SERVER['REMOTE_ADDR']`). For example, for a client 
with IP address `18.18.18.18` and 2 trusted proxies - `2.2.2.2` and `8.8.8.8`, the configuration will be: 

```php
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

/** @var TrustedHostsNetworkResolver $middleware */
$middleware = $middleware->withTrustedIps([['8.8.8.8', '2.2.2.2', '18.18.18.18']]);
```

The order of IPs is not important.

#### Forwarded header groups

Header groups to parse the data from. By including headers in this list, they are trusted automatically.

The default is:

```php
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

/** @var TrustedHostsNetworkResolver $middleware */
$middleware = $middleware->withForwardedHeaderGroups([    
    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,
    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,           
]);
```

which is an alternative/shorter way of writing this:

```php
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

/** @var TrustedHostsNetworkResolver $middleware */
$middleware = $middleware->withForwardedHeaderGroups([    
    'forwarded',
    [
        'ip' => 'x-forwarded-for',
        'protocol' => 'x-forwarded-proto',
        'host' => 'x-forwarded-host',
        'port' => 'x-forwarded-port',    
    ],           
]);
```

The accepted values are:

- `TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC` string constant. Parse all data from single `Forwarded` 
header according to [RFC 7239](https://datatracker.ietf.org/doc/html/rfc7239).
- Array. Parse data from separate forwarded headers with "X" prefix. Unlike with RFC variation, each header stores only
one data unit (for example, IP). Headers with "X" prefix are quite common despite being non-standard:
  - [X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For) - IP.
  - [X-Forwarded-Proto](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Proto) - protocol.
  - [X-Forwarded-Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host) - host.
  - `X-Forwarded-Port` - port.

The header groups are processed in the order they are defined. If the header containing IP is present and is non-empty, 
this group will be selected and further ones will be ignored.

You can add support for custom headers and/or change priority:

```php
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

/** @var TrustedHostsNetworkResolver $middleware */
$middleware = $middleware->withForwardedHeaderGroups([    
    [
        'ip' => 'y-forwarded-for',
        'protocol' => 'y-forwarded-proto',
        'host' => 'y-forwarded-host',
        'port' => 'y-forwarded-port',    
    ],
    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,    
    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,               
]);
```

For protocol, it's also possible to resolve non-standard values via mapping:

```php
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

/** @var TrustedHostsNetworkResolver $middleware */
$middleware = $middleware->withForwardedHeaderGroups([
    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,    
    [
        'ip' => 'y-forwarded-for',
        'protocol' => [
            'front-end-https', 
            ['on' => 'https'],
        ],
        'host' => 'y-forwarded-host',
        'port' => 'y-forwarded-port',    
    ],
    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,               
]);
```

or via callable:

```php
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

/** @var TrustedHostsNetworkResolver $middleware */
$middleware = $middleware->withForwardedHeaderGroups([
    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,    
    [
        'ip' => 'y-forwarded-for',
        'protocol' => [
            'front-end-https', 
            static fn (string $protocol): ?string => $protocol === 'On' ? 'https': 'http',,
        ],
        'host' => 'y-forwarded-host',
        'port' => 'y-forwarded-port',    
    ],
    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,               
]);
```

It's also a good idea to limit default header groups to the only guaranteed sources of data:

```php
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

/** @var TrustedHostsNetworkResolver $middleware */
$middleware = $middleware->withForwardedHeaderGroups([    
    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,           
]);
```

#### Typical forwarded headers

List of headers that are considered related to forwarding.

The default is:

```php
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

/** @var TrustedHostsNetworkResolver $middleware */
$middleware = $middleware->withTypicalForwardedHeaders([
    // RFC
    'forwarded',

    // "X" prefix
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-forwarded-port',

    // Microsoft
    'front-end-https',
]);
```

The headers that are present in this list but missing in matching forwarded header group will be deleted from request 
because they are potentially not secure and likely were not passed by a proxy server.

For example, with default forwarded header groups' setup used as well:

```php
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

/** @var TrustedHostsNetworkResolver $middleware */
$middleware = $middleware->withForwardedHeaderGroups([
    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_RFC,
    TrustedHostsNetworkResolver::FORWARDED_HEADER_GROUP_X_PREFIX,
]);
```

and with the following request headers passed:

```php
[
    'Forwarded' => [
        'for="9.9.9.9:8013";proto=http;host=example13.com',
        'for="8.8.8.8:8012";proto=http;host=example12.com',
        'for="2.2.2.2:8011";proto=http;host=example11.com',
    ],
    'X-Forwarded-For' => 'not-secure',
    'X-Forwarded-Host' => 'not-secure',
    'X-Forwarded-Proto' => 'not-secure',
    'X-Forwarded-Port' => 'not-secure',
    'Front-End-Https' => 'not-secure',
    'Non-Forwarded' => 'not-typical',
];
```

middleware will remove these headers from request:

- `x-forwarded-for`.
- `x-forwarded-host`.
- `x-forwarded-proto`.
- `x-forwarded-port`.
- `front-end-https`.

because RFC group is matching and the rest can't be trusted. The headers that are not declared as typical forwarded 
headers will be left as is (`Non-Forwarded` in the example above).

#### Accessing resolved data

Resolved IP is saved to a special request's attribute:

```php
use Psr\Http\Message\ServerRequestInterface;

/** @var ServerRequestInterface $request */
$ip = $request->getAttribute(TrustedHostsNetworkResolver::ATTRIBUTE_REQUEST_CLIENT_IP);
```

There is an additional attribute allowing to retrieve all previous validated and trusted connection chain items. It 
needs explicit configuration:

```php
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

/** @var TrustedHostsNetworkResolver $middleware */
$middleware = $middleware->withConnectionChainItemsAttribute('connectionChainItems');
// ...
/** @var ServerRequestInterface $request */
$connectionChainItems = $request->getAttribute('connectionChainItems');
``` 

An example of contents:

```php
[
    [
        'ip' => '18.18.18.18',
        'protocol' => null,
        'host' => null,
        'port' => null,
        'ipIdentifier' => null,
    ],
    [
        'ip' => '2.2.2.2',
        'protocol' => 'http',
        'host' => 'example1.com',
        'port' => null,
        'ipIdentifier' => '_obfuscated1',
    ]
],
```

#### Reverse-obfuscating IP identifier

You may extend middleware class and provide reverse-obfuscating logic for 
[obfuscated](https://datatracker.ietf.org/doc/html/rfc7239#section-6.3) IP identifiers:

```php
use Yiisoft\ProxyMiddleware\TrustedHostsNetworkResolver;

class MyTrustedHostsNetworkResolver extends TrustedHostsNetworkResolver
{
    protected function reverseObfuscateIpIdentifier(
        string $ipIdentifier,
        array $validatedConnectionChainItems,
        array $remainingConnectionChainItems,
        RequestInterface $request,
    ): ?array
    {
        return match ($ipIdentifier) {
            '_obfuscated1' => ['2.2.2.2', null], // Without port
            '_obfuscated2' => ['5.5.5.5', '8082'], // With port
            default => null, // Unable to resolve (default)
        };
    }
}
```

## Testing

### Unit testing

The package is tested with [PHPUnit](https://phpunit.de/). To run tests:

```shell
./vendor/bin/phpunit
```

### Mutation testing

The package tests are checked with [Infection](https://infection.github.io/) mutation framework with
[Infection Static Analysis Plugin](https://github.com/Roave/infection-static-analysis-plugin). To run it:

```shell
./vendor/bin/roave-infection-static-analysis-plugin
```

### Static analysis

The code is statically analyzed with [Psalm](https://psalm.dev/). To run static analysis:

```shell
./vendor/bin/psalm
```

### Code style

Use [Rector](https://github.com/rectorphp/rector) to make codebase follow some specific rules or 
use either newest or any specific version of PHP: 

```shell
./vendor/bin/rector
```

### Dependencies

Use [ComposerRequireChecker](https://github.com/maglnet/ComposerRequireChecker) to detect transitive 
[Composer](https://getcomposer.org/) dependencies.

## License

The Yii Proxy Middleware is free software. It is released under the terms of the BSD License.
Please see [`LICENSE`](./LICENSE.md) for more information.

Maintained by [Yii Software](https://www.yiiframework.com/).

## Support the project

[![Open Collective](https://img.shields.io/badge/Open%20Collective-sponsor-7eadf1?logo=open%20collective&logoColor=7eadf1&labelColor=555555)](https://opencollective.com/yiisoft)

## Follow updates

[![Official website](https://img.shields.io/badge/Powered_by-Yii_Framework-green.svg?style=flat)](https://www.yiiframework.com/)
[![Twitter](https://img.shields.io/badge/twitter-follow-1DA1F2?logo=twitter&logoColor=1DA1F2&labelColor=555555?style=flat)](https://twitter.com/yiiframework)
[![Telegram](https://img.shields.io/badge/telegram-join-1DA1F2?style=flat&logo=telegram)](https://t.me/yii3en)
[![Facebook](https://img.shields.io/badge/facebook-join-1DA1F2?style=flat&logo=facebook&logoColor=ffffff)](https://www.facebook.com/groups/yiitalk)
[![Slack](https://img.shields.io/badge/slack-join-1DA1F2?style=flat&logo=slack)](https://yiiframework.com/go/slack)

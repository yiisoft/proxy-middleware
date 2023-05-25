<p align="center">
    <a href="https://github.com/yiisoft" target="_blank">
        <img src="https://yiisoft.github.io/docs/images/yii_logo.svg" height="100px">
    </a>
    <h1 align="center">Yii _____</h1>
    <br>
</p>

[![Latest Stable Version](https://poser.pugx.org/yiisoft/_____/v/stable.png)](https://packagist.org/packages/yiisoft/_____)
[![Total Downloads](https://poser.pugx.org/yiisoft/_____/downloads.png)](https://packagist.org/packages/yiisoft/_____)
[![Build status](https://github.com/yiisoft/_____/workflows/build/badge.svg)](https://github.com/yiisoft/_____/actions?query=workflow%3Abuild)
[![Code Coverage](https://codecov.io/gh/yiisoft/_____/branch/master/graph/badge.svg)](https://codecov.io/gh/yiisoft/_____)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fyiisoft%2F_____%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/yiisoft/_____/master)
[![static analysis](https://github.com/yiisoft/_____/workflows/static%20analysis/badge.svg)](https://github.com/yiisoft/_____/actions?query=workflow%3A%22static+analysis%22)
[![type-coverage](https://shepherd.dev/github/yiisoft/_____/coverage.svg)](https://shepherd.dev/github/yiisoft/_____)
[![psalm-level](https://shepherd.dev/github/yiisoft/_____/level.svg)](https://shepherd.dev/github/yiisoft/_____)

The package ...

## Requirements

- PHP 8.1 or higher.

## Installation

The package could be installed with composer:

```shell
composer require yiisoft/_____
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

Trusted hosts network resolver can set IP, protocol, host, URL, and port based on trusted headers such as
`Forward` or `X-Forwarded-Host` coming from trusted hosts you define. Usually these are load balancers.

Make sure that the trusted host always overwrites or removes user-defined headers to avoid security issues.

```php
/**
 * @var Psr\Http\Message\ServerRequestInterface $request
 * @var Psr\Http\Server\RequestHandlerInterface $handler
 * @var Yiisoft\Yii\Middleware\TrustedHostsNetworkResolver $middleware
 */

$middleware = $middleware->withAddedTrustedHosts(
    // List of secure hosts including `$_SERVER['REMOTE_ADDR']`. You can specify IPv4, IPv6, domains, and aliases.
    hosts: ['1.1.1.1', '2.2.2.1/3', '2001::/32', 'localhost'],
    // IP list headers. Headers containing many sub-elements (e.g. RFC 7239) must also be listed for other relevant
    // types (such as host headers), otherwise they will only be used as an IP list.
    ipHeaders: ['x-forwarded-for', [TrustedHostsNetworkResolver::IP_HEADER_TYPE_RFC7239, 'forwarded']],
    // Protocol headers with accepted protocols and corresponding header values. Matching is case-insensitive.
    protocolHeaders: ['x-forwarded-proto' => ['https' => 'on']],
    // List of headers containing HTTP host.
    hostHeaders: ['forwarded', 'x-forwarded-for'],
    // List of headers containing HTTP URL.
    urlHeaders: ['x-rewrite-url'],
    // List of headers containing port number.
    portHeaders:['x-rewrite-port'],
    // List of trusted headers. For untrusted hosts, middleware removes these from the request.
    trustedHeaders: ['x-forwarded-for', 'forwarded'],
);
// Disable earlier settings:
$middleware = $middleware->withoutTrustedHosts();

$response = $middleware->process($request, $handler);
```

Additionally, you can specify the following options:

```php
/**
 * Specify a request attribute name to which middleware writes trusted path data.
 * 
 * @var Yiisoft\Yii\Middleware\TrustedHostsNetworkResolver $middleware
 * @var string|null $attribute
 */
$middleware = $middleware->withAttributeIps($attribute);

/**
 * Specify client IP validator.
 * 
 * @var Yiisoft\Validator\ValidatorInterface $validator
 */
$middleware = $middleware->withValidator($validator);
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

The Yii _____ is free software. It is released under the terms of the BSD License.
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

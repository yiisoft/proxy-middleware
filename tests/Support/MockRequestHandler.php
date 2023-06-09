<?php

declare(strict_types=1);

namespace Yiisoft\ProxyMiddleware\Tests\Support;

use HttpSoft\Message\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Throwable;
use Yiisoft\Http\Status;

final class MockRequestHandler implements RequestHandlerInterface
{
    public ?ServerRequestInterface $processedRequest = null;
    private ?Throwable $handleException = null;

    public function __construct(private int $responseStatusCode = Status::OK)
    {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($this->handleException !== null) {
            throw $this->handleException;
        }

        $this->processedRequest = $request;

        return new Response($this->responseStatusCode);
    }
}

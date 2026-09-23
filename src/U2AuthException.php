<?php

declare(strict_types=1);

namespace U2Secured\U2Auth;

/**
 * Note: getCode() returns the U2 error code STRING (e.g. ENROLMENT_NOT_FOUND),
 * not an integer. As of PHP 8.5, Exception::getCode() (along with
 * getMessage(), getFile(), getLine(), getTrace(), getPrevious()) is final and
 * cannot be overridden -- so instead of declaring our own getCode(), we stash
 * the string directly into the inherited (untyped) $code property in the
 * constructor and let the final getCode() return it verbatim. This is the
 * same trick PDOException uses to return string SQLSTATE codes, and it works
 * unchanged on both the PHP 7.4 floor this SDK targets (where getCode() was
 * never final) and PHP 8.5+. The HTTP status lives on getStatusCode().
 */
final class U2AuthException extends \Exception
{
    /** @var int */
    private $statusCode;

    public function __construct(int $statusCode, string $errorCode, string $message)
    {
        parent::__construct(sprintf('U2Auth API error %d %s: %s', $statusCode, $errorCode, $message));
        $this->statusCode = $statusCode;
        $this->code = $errorCode;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }
}

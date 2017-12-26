<?php

namespace PHPHttpAuth\Adaptors;

use PHPHttpAuth\AbstractAdaptor;
use PHPHttpAuth\PHPHttpAuth;

class AuthBasic extends AbstractAdaptor
{
    public function sendHeaders()
    {
        header(sprintf('WWW-Authenticate: Basic realm="%s"', $this->realm));
        header("HTTP/1.0 401 Unauthorized");
    }

    public function verify($username, $password)
    {
        $x = 0;
        if (!(sha1($this->getUsername()) === sha1($username))) {
            $x &= PHPHttpAuth::AUTH_USERNAME_WRONG;
        }
        if (!(sha1($this->getPassword()) === sha1($password))) {
            $x &= PHPHttpAuth::AUTH_PASSWORD_WRONG;
        }
        return $x;
    }

    public function getUsername()
    {
        return isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : false;
    }

    public function getPassword()
    {
        return isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : false;
    }
}
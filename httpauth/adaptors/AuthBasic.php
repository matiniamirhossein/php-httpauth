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
            $x |= PHPHttpAuth::AUTH_USERNAME_WRONG;
        }
        if (!(sha1($this->getPassword()) === sha1($password))) {
            $x |= PHPHttpAuth::AUTH_PASSWORD_WRONG;
        }
        return $x;
    }

    public function getUsername()
    {
        return $this->parse()['username'];
    }

    public function parse()
    {
        $username = $password = null;
        if (array_key_exists('PHP_AUTH_USER', $_SERVER)) { // mod_php
            $username = $_SERVER['PHP_AUTH_USER'];
            $password = array_key_exists('PHP_AUTH_PW', $_SERVER) ? $_SERVER['PHP_AUTH_PW'] : null;
        } elseif (array_key_exists('HTTP_AUTHENTICATION', $_SERVER)) { // most other servers
            if (strpos(strtolower($_SERVER['HTTP_AUTHENTICATION']), 'basic') === 0) {
                $userdata = explode(':', base64_decode(substr($_SERVER['HTTP_AUTHENTICATION'], 6)));
                list($username, $password) = $userdata;
            }
        }
        return ['username' => $username, 'password' => $password];
    }

    public function getPassword()
    {
        return $this->parse()['password'];
    }
}
<?php

namespace PHPHttpAuth;

use PHPHttpAuth\Adaptors\AuthBasic;
use PHPHttpAuth\Adaptors\AuthDigest;
use PHPHttpAuth\Exceptions\PHPHttpAuthException;

class PHPHttpAuth
{
    const AUTH_TYPE_BASIC = 'basic';
    const AUTH_TYPE_DIGEST = 'digest';
    const SUCCESS = 0;
    const AUTH_USERNAME_WRONG = 1;
    const AUTH_PASSWORD_WRONG = 2;
    const AUTH_RESPONSE_WRONG = 4;
    /** @var AbstractAdaptor */
    private $adaptor;

    /**
     * PHPHttpAuth constructor.
     * @param $authType
     * @throws PHPHttpAuthException
     */
    public function __construct($authType)
    {
        if ($authType == self::AUTH_TYPE_BASIC) {
            $this->adaptor = new AuthBasic();
        } else if ($authType == self::AUTH_TYPE_DIGEST) {
            $this->adaptor = new AuthDigest();
        } else if ($authType !== false) {
            throw new PHPHttpAuthException("Invalid authentication type.");
        }
    }

    public function verify($realm, $username, $password, $exitAndSendHeadersOnFail = true)
    {
        $this->adaptor->setRealm($realm);
        $result = $this->adaptor->verify($username, $password);
        if ($result === self::SUCCESS) {
            return true;
        }
        if ($exitAndSendHeadersOnFail) {
            $this->adaptor->sendHeaders();
            if ($result === self::AUTH_USERNAME_WRONG) {
                die("Invalid username provided.");
            } else if ($result === self::AUTH_PASSWORD_WRONG) {
                die("Invalid password provided.");
            } else if ($result === self::AUTH_RESPONSE_WRONG) {
                die("Invalid response provided.");
            }
        }
        return $result;
    }

    /**
     * Get username so you can provide a password for that username if you support multiple users
     * @return string
     */
    public function getUsername()
    {
        return $this->adaptor->getUsername();
    }

    /**
     * @return AbstractAdaptor
     */
    public function getAdaptor()
    {
        return $this->adaptor;
    }

    /**
     * @param AbstractAdaptor $adaptor
     */
    public function setAdaptor(AbstractAdaptor $adaptor)
    {
        $this->adaptor = $adaptor;
    }
}
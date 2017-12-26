<?php

namespace PHPHttpAuth\Adaptors;

use function addslashes;
use PHPHttpAuth\AbstractAdaptor;
use PHPHttpAuth\PHPHttpAuth;

class AuthDigest extends AbstractAdaptor
{
    private $data = [];

    public function __construct()
    {
        $this->data = $this->httpDigestParse($_SERVER['PHP_AUTH_DIGEST']);
    }

    public function getUsername()
    {
        return $this->data['username'];
    }

    private function httpDigestParse($txt)
    {
        // protect against missing data
        $needed_parts = ['nonce' => 1, 'nc' => 1, 'cnonce' => 1, 'qop' => 1, 'username' => 1, 'uri' => 1, 'response' => 1];
        $data = [];
        $keys = implode('|', array_keys($needed_parts));

        preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $txt, $matches, PREG_SET_ORDER);

        foreach ($matches as $m) {
            $data[$m[1]] = $m[3] ? $m[3] : $m[4];
            unset($needed_parts[$m[1]]);
        }

        return $needed_parts ? false : $data;
    }

    public function sendHeaders()
    {
        header('HTTP/1.1 401 Unauthorized');
        header(sprintf('WWW-Authenticate: Digest realm="%s", qop="auth", nonce="%s",opaque="%s"', $this->realm, uniqid(), md5($this->realm)));
    }


    private function getValidResponse($password)
    {
        $A1 = md5($this->data['username'] . ':' . $this->realm . ':' . $password);
        $A2 = md5($_SERVER['REQUEST_METHOD'] . ':' . $this->data['uri']);
        return md5($A1 . ':' . $this->data['nonce'] . ':' . $this->data['nc'] . ':' . $this->data['cnonce'] . ':' . $this->data['qop'] . ':' . $A2);
    }


    public function verify($username, $password)
    {
        //rebuild auth data
        $this->data = $this->httpDigestParse($_SERVER['PHP_AUTH_DIGEST']);
        $x = 0;
        if (!(strcmp($this->data['username'], $username) === 0)) {
            $x &= PHPHttpAuth::AUTH_USERNAME_WRONG;
        }
        if (!(strcmp($this->data['response'], $this->getValidResponse($password)) === 0)) {
            $x &= PHPHttpAuth::AUTH_RESPONSE_WRONG;
        }
        return $x;
    }
}
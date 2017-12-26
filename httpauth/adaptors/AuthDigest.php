<?php
namespace PHPHttpAuth\Adaptors;
use PHPHttpAuth\AbstractAdaptor;
use PHPHttpAuth\PHPHttpAuth;

class AuthDigest extends AbstractAdaptor
{
    private $data = [];

    public function __construct()
    {
        $this->data = $this->httpDigestParse();
    }

    public function getUsername()
    {
        return $this->data['username'];
    }

    private function httpDigestParse()
    {
        // protect against missing data
        $needed_parts = ['nonce' => 1, 'nc' => 1, 'cnonce' => 1, 'qop' => 1, 'username' => 1, 'uri' => 1, 'response' => 1];
        $data = [];
        $keys = implode('|', array_keys($needed_parts));

        preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', self::getAuthDigest(), $matches, PREG_SET_ORDER);

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
        $request_method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
        $A1 = md5(sprintf('%s:%s:%s', $this->data['username'], $this->realm, $password));
        $A2 = md5(sprintf('%s:%s', $request_method, $this->data['uri']));
        $response = md5(sprintf('%s:%s:%s:%s:%s:%s', $A1, $this->data['nonce'], $this->data['nc'], $this->data['cnonce'], $this->data['qop'], $A2));
        return $response;
    }


    public function verify($username, $password)
    {
        //rebuild auth data
        $this->data = $this->httpDigestParse();
        $x = 0;
        if (!(strcmp($this->data['username'], $username) === 0)) {
            $x |= PHPHttpAuth::AUTH_USERNAME_WRONG;
        }
        if (!(strcmp($this->data['response'], $this->getValidResponse($password)) === 0)) {
            $x |= PHPHttpAuth::AUTH_RESPONSE_WRONG;
        }
        return $x;
    }

    private function getAuthDigest()
    {
        $digest = null;
        if (isset($_SERVER['PHP_AUTH_DIGEST'])) {
            $digest = $_SERVER['PHP_AUTH_DIGEST'];
        } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            if (strpos(strtolower($_SERVER['HTTP_AUTHORIZATION']), 'digest') === 0) {
                $digest = substr($_SERVER['HTTP_AUTHORIZATION'], 7);
            }
        }
        return $digest;
    }
}
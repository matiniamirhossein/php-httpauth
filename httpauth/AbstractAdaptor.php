<?php
namespace PHPHttpAuth;
abstract class AbstractAdaptor
{
    protected $realm;
    public function setRealm($realm){
        $this->realm = \addslashes($realm);
    }

    public abstract function sendHeaders();
    public abstract function getUsername();
    public abstract function verify($username, $password);
}
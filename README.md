**Simple php http auth library using http auth basic/digest.**

**Examples:**
```php
<?php
use PHPHttpAuth\PHPHttpAuth;
//basic auth
$httpAuth = new PHPHttpAuth(PHPHttpAuth::AUTH_TYPE_BASIC);
$httpAuth->verify("Protected area", "amir", "1234");

//digest auth
$httpAuth = new PHPHttpAuth(PHPHttpAuth::AUTH_TYPE_DIGEST);
$httpAuth->verify("Protected area", "amir", "1234");
```
You can also disable auto handling and handle the response yourself. (I don't know the use case though).
```php
<?php
use PHPHttpAuth\PHPHttpAuth;
$httpAuth = new PHPHttpAuth(PHPHttpAuth::AUTH_TYPE_BASIC);
$result = $httpAuth->verify("Protected area", "amir", "1234", false);
if($result !== TRUE){
	//what to do when failed
	$httpAuth->getAdaptor()->sendHeaders();
	if ($result === PHPHttpAuth::AUTH_USERNAME_WRONG) {
	    die("Invalid username provided.");
    } else if ($result === PHPHttpAuth::AUTH_PASSWORD_WRONG) {
        die("Invalid password provided."); //basic auth only
    } else if ($result === PHPHttpAuth::AUTH_RESPONSE_WRONG) {
        die("Invalid response provided."); //digest auth only
	}
}
echo "Authentication succeed.";
```
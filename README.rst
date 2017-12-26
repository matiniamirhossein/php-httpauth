Simple php http auth library using http auth basic/digest.
Examples:
Http Digest Auth:
.. code:: php
$httpAuth = new PHPHttpAuth(PHPHttpAuth::AUTH_TYPE_BASIC);
$httpAuth->verify("Protected area", "amir", "1234");`
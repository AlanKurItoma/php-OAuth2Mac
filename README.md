# php-OAuth2MacToken

This is MAC Access Authentication Utility Class Library for the OAuth 2.0 related protocol.

I've taken the original and updated it for my purposes, that is, support for the v1 protocol 
instead of the now deprecated v0 protocol.

## Files

*   lib/OAuth2MacTokenUtil.php       : Calcurate MAC, and Generate AuthZ Header String

## Usage

Please look at the source files for usage - I've not removed all the cruft, and haven't tested everything. Here's what I'm using it for:

		include_once("php-OAuth2MacToken/OAuth2MacTokenServer.php");

		$server = new OAuth2MacTokenServer();
		$server->setSecret("489dks293j39");
		$server->setAlgorithm("hmac-sha-1");
		$server->setRequestURL("http://example.com:80/resource/1?b=1&a=2");
		$server->validateSignature();


## Original Author

*   [@ritou](http://twitter.com/ritou)
*   [Blog](http://d.hatena.ne.jp/ritou)
*   ritou.06 _at_ gmail.com

## References

*   [HTTP Authentication: MAC Access Authentication](http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01)
*   [Original Project](https://github.com/ritou/php-OAuth2MacToken)
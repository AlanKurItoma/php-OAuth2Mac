# php-OAuth2MAC

This is MAC Authentication Utility Class Library for the [draft OAuth 2.0 related protocol](http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01). It's based on a v0 protocol project by [ritou](https://github.com/ritou/php-OAuth2MacToken), but altered to support the current, v1 protocol. I've also restructured it a little to be more useful for my purposes.

## Files

*   OAuth2Mac/Client.php  : Convenience class to generate a request using MAC
*   OAuth2Mac/Server.php  : Convenience class for extracting and validating request information
*   OAuth2Mac/Util.php    : Tools to calculate the MAC, and generate the Authorization header string

## Usage

The source files are reasonably easy to work out the usage from, and I haven't removed all cruft and tested everything yet. Here's how I'm using it:

		include_once("OAuth2Mac/Server.php");

		$server = new OAuth2MacTokenServer();
		$server->setSecret("489dks293j39");
		$server->setAlgorithm("hmac-sha-1");
		$server->setRequestURL("http://example.com:80/resource/1?b=1&a=2");
		$server->validateSignature();

## Caveats
  - I've only really been using the `Server`; so the `Client` and examples should be considered untested.
  - This only validates the request or generates the signatures. It doesn't access a database to retrieve the secret key information, or validate the non-repetition of nonces.
  - Timestamp checking is only done manually - `Server::validateTimestamp` should be called with the fuzz value that you want.
  - Key distribution is completely out of scope of this package
  - The `ext` parameter is not handled properly
  - The well-formed-ness tests are not complete, and not well tested
  - Unit testing needs to be re-written to work.

## Author

*   [Nicholas Devenish](https://github.com/ndevenish/)
*   ndevenish _at_ gmail.com
*   Heavily based on code by [@ritou](http://twitter.com/ritou)

## References

*   [HTTP Authentication: MAC Access Authentication](http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01)
*   [The OAuth 2.0 Authorization Framework](http://tools.ietf.org/html/draft-ietf-oauth-v2)
*   [Original Project](https://github.com/ritou/php-OAuth2MacToken)
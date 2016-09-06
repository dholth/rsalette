rsalette
========

Compact pure-Python RSA verification.

rsalette provides a compact, < 200 lines, pure-Python 2+3, single file
RSA verification library that is compatible with JSON Web Key.

rsalette is alpha quality software.

Usage::

	import rsalette
	verifier = rsalette.PublicKey.from_jwk({'kty':'RSA', 'e':'AQAB', 'n': ...})
	verified_message = verifier.verify(message, signature)

For JSON Web Token::

	openid_configuration = { ... } # value from .well-known/openid-configuration
	id_token = '...' # value from OpenID Connect remote user
	jwks = requests.get(openid_configuration['jwks_uri']).json()
	payload = rsalette.verify_jwt(id_token, jwks)

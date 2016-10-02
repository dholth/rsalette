rsalette
========

Compact pure-Python RSA verification.

rsalette provides a compact, < 200 lines, pure-Python 2+3, single file
RSA verification library that is compatible with JSON Web Key.

It includes a JSON Web Signature (JWS) / JSON Web Token (JWT)
verifier that can be used for OpenID Connect.

It includes asn1lette, a limited asn.1 parser that can parse RSA public
keys from PEM or DER data.

rsalette comes with no warranty, but if you'd like to do an audit,
it's short.

Usage::

	import rsalette
	verifier = rsalette.PublicKey.from_jwk({'kty':'RSA', 'e':'AQAB', 'n': ...})
	verified_message = verifier.verify(message, signature)

For JSON Web Token::

	openid_configuration = { ... } # value from .well-known/openid-configuration
	id_token = '...' # value from OpenID Connect remote user
	jwks = requests.get(openid_configuration['jwks_uri']).json()
	payload = rsalette.verify_jwt(id_token, jwks)

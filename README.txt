rsalette
========

Compact pure-Python RSA verification.

rsalette provides a compact, pure-Python 2+3, single file RSA verification
library that is compatible with JSON Web Key.

rsalette is alpha quality software.

Usage::

	import rsalette
	verifier = rsalette.PublicKey.from_jwk({'kty':'RSA', 'e':'AQAB', 'n': ...})
	verified_message = verifier.verify(message, signature)

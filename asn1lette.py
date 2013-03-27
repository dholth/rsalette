# -*- coding: utf-8 -*-
# Just enough ASN.1 DER parsing to get an openssl RSA public key.
# The raw public key is just a sequence of the two integers (n, e)

from base64 import b64decode
from binascii import hexlify
from itertools import chain

__all__ = ['parse_pem', 'parse_der']

def parse_pem(pem):
    """Parse ASN.1 from an iterable yielding PEM lines."""
    der = chain.from_iterable(pem_to_bytearrays(pem))
    return parse_der(der)

def parse_der(der):
    """Parse ASN.1 from an iterable yielding DER bytes."""
    return _parse(iter(der))

def _parse(der):
    # Type tag
    ttag = next(der)
    ttype = ttag & 0x1f
    tcls = (ttag & 0b11000000) >> 6 
    constructed = bool((ttag & 0b100000) >> 5)
    
    # The variable-length length field.
    llen = next(der)
    if not llen & 0x80:
        length = llen
    else:
        length = 0
        for i in range(llen ^ 0x80):
            length <<= 8
            length += next(der)

    body = (next(der) for i in range(length))

    if ttag == 0x30: # SEQUENCE
        def seqbody():
            while True:
                yield _parse(body)
        items = list(seqbody())
        return items
    elif ttag == 0x02: # INTEGER
        return int(hexlify(bytearray(body)), 16)
    elif ttag in (0x04, 0x03): # OCTET STRING, BIT STRING
        return bytearray(body)
    elif constructed:
        return (ttag, ttype, tcls, constructed, _parse(body))
    else:
        return (ttag, ttype, tcls, constructed, bytearray(body))

def pem_to_bytearrays(pem):
    line = next(pem)
    while not line.startswith(b'-----BEGIN'):
        line = next(pem)
    line = next(pem)
    while not line.startswith(b'-----END'):
        yield bytearray(b64decode(line))
        line = next(pem)

if __name__ == "__main__": # pragma nocover
    import sys, pprint
    pprint.pprint(parse_pem(sys.stdin))
    

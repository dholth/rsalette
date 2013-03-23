"""
Simple pure-Python signature-verification-only RSA implementation.
"""

import base64
import binascii
import hashlib
import re

__all__ = ['PublicKey']

# Important to make sure these values have no regex special characters:
ASN1_HASH = {
    b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20' : 'sha256',
    b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30' : 'sha384',
    b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40' : 'sha512'
}

pkcs_regex = (b'\x01\xff+\x00(?P<algorithm>' +
              b'|'.join(ASN1_HASH.keys()) +
              b')(?P<hash>.*)$')

pkcs_signature = re.compile(pkcs_regex)

class PublicKey(object):
    KTY = "RSA"
    
    def __init__(self, n, e):
        self.e = e
        self.n = n
     
    @classmethod
    def from_jwk(cls, jwk):
        """Load RSA PublicKey from a JSON Web Key"""
        if jwk['kty'] != cls.KTY:
            raise ValueError("Not a {0} key".format(cls.KTY))
        n = b64_to_int(as_binary(jwk['n']))
        e = b64_to_int(as_binary(jwk['e']))
        return cls(n, e)
    
    def to_jwk(self):
        """Return a JSON Web Key for this key."""
        jwk = {'kty':self.KTY, 
               'n':as_text(int_to_b64(self.n)),
               'e':as_text(int_to_b64(self.e))}
        return jwk
    
    def verify(self, message, signature):
        """Verify a message signed with this key. Return the verified message on success.

        Input, output are bytes."""
        signature_integer = bytes_to_int(signature)
        plain_signature = decrypt(signature_integer, self)
        plain_signature_bytes = int_to_bytes(plain_signature)
        match = pkcs_signature.match(plain_signature_bytes)
        if match:
            hash = hashlib.new(ASN1_HASH[match.group(1)])
            hash.update(message)
            if hash.digest() == match.group(2):
                return message            
        raise ValueError("Bad signature")
    
    def __repr__(self):
        return "{0}(n={1},e={2})".format(self.__class__.__name__, self.n, self.e)

def decrypt(ciphertext, pub):
    """RSA decryption on integers"""
    return pow(ciphertext, pub.e, pub.n)

def urlsafe_b64encode(data):
    """urlsafe_b64encode without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b'=')

def urlsafe_b64decode(data):
    """urlsafe_b64decode without padding"""
    pad = b'=' * (4 - (len(data) & 3))
    return base64.urlsafe_b64decode(data + pad)

def bytes_to_int(data):
    """Convert bytes to an integer"""
    hexy = binascii.hexlify(data)
    hexy = b'0'*(len(hexy)%2) + hexy
    return int(hexy, 16)

def b64_to_int(data):
    """Convert urlsafe_b64encode(data) to an integer"""
    return bytes_to_int(urlsafe_b64decode(data))

def int_to_bytes(integer):
    hexy = as_binary('%x' % integer)
    hexy = b'0'*(len(hexy)%2) + hexy
    data = binascii.unhexlify(hexy)
    return data

def int_to_b64(integer):
    """Convert an integer to urlsafe_b64encode() data"""
    return urlsafe_b64encode(int_to_bytes(integer))

def as_binary(text):
    return text.encode('latin1')

def as_text(data):
    return data.decode('latin1')

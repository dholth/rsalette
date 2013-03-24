# -*- coding: utf-8 -*-
#
# Copyright 2013 Daniel Holth <dholth@gmail.com>
# Based on python-rsa copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Simple pure-Python signature-verification-only RSA implementation.
"""

import base64
import binascii
import hashlib
import re

__all__ = ['PublicKey']

ASN1_HASH = {b'0Q0\r\x06\t`\x86H\x01e\x03\x04\x02\x03\x05\x00\x04@': 'sha512', 
             b'0A0\r\x06\t`\x86H\x01e\x03\x04\x02\x02\x05\x00\x040': 'sha384', 
             b'010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 ': 'sha256'}
             
pkcs_regex = (b'\x01\xff+\x00(?P<algorithm>' +
              b'|'.join(sorted(re.escape(asn1) for asn1 in ASN1_HASH.keys())) +
              b')(?P<hash>.+)')

pkcs_signature = re.compile(pkcs_regex, re.DOTALL)

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

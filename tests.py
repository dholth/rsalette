import rsalette
import subprocess
import json
import tempfile
import os.path

from nose.tools import eq_, raises

keys = [            
        {'e': 'AQAB', 
         'kty': 'RSA', 
         'n': 'tbg-f-iI33OW7Pll0eah8mmAz-5kQWntKRzP3Bd3dB93523t0ZQEhS17wR4TLOgKBGDGhncMvWUH53-pPWxkDanPXpQ53mK4McQfA6PE__XrgUI_DfpuK-46HJecJnyKcghrSUKkKAM9ZU46zVRsmr84t8IKBwRwzdqfOT3UJEbB3ktqw-1UNsz0ZmBAeZXnETbBGwSo3tTeHOVq0E6kYqmlaO0Eu1jfN8mxLhc1x7_9osjsbO0pkJTchdaVBl7MLpmYNfwlh3eAzir__avGXetJa9fpsP2KAG0_6OSlTh2MzwyuTRTqmU0rQQOHscqoM8VubFH5odRcca3lHFFb0Q'}
       ]

def test_rsalette():
    in_jwk = keys[0]
    pk = rsalette.PublicKey.from_jwk(in_jwk)
    jwk = pk.to_jwk()
    for param in ('kty', 'n', 'e'):
        eq_(jwk[param], in_jwk[param])
    
    assert 'PublicKey(' in repr(pk)
   
@raises(ValueError)
def test_bad_key():
    rsalette.PublicKey.from_jwk({'kty':'ARS'})

# Generating a suitable keypair:
#
# openssl genrsa -out test_private.pem 2048
# (the python-rsa library was used to extract the public key)

def test_signature():
    for digest in 'sha256', 'sha384', 'sha512':
        _test_signature(digest)
        
def _test_signature(digest='sha256'):
    our_pubkey = rsalette.PublicKey.from_jwk(keys[0])
    here = os.path.abspath(os.path.dirname(__file__))
    with tempfile.NamedTemporaryFile() as temp_message:
        with tempfile.NamedTemporaryFile() as temp_signature:
            message = json.dumps(keys[0]).encode('utf-8')
            temp_message.write(message)
            temp_message.flush()
            # pkcs signing with openssl    
            subprocess.call(['openssl', 'dgst', '-' + digest, 
                             '-sign', os.path.join(here, 'test_private.pem'),
                             '-out', temp_signature.name,
                             temp_message.name])            
            signature = temp_signature.read()
    verified_message = our_pubkey.verify(message, signature)
    eq_(verified_message, message)
    
    @raises(ValueError)
    def bad_signature():
        our_pubkey.verify(message+b' ', signature)
        
    bad_signature()

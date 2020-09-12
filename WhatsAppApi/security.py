from base64 import b64encode, b64decode

import curve25519
import hashlib
from hkdf import hkdf_expand

import hmac

from Crypto import Random
from Crypto.Cipher import AES

def get_enc_mac_keys(encoded_secret, privateKey):
    secret = b64decode(encoded_secret)
    if len(secret) != 144:
        raise ValueError('Invalid secret size')

    sharedSecret = privateKey.get_shared_key(curve25519.Public(secret[:32]), lambda a:a)

    key_material = Hmac(b'\0' * 32).hash(sharedSecret)
    sharedSecretExpanded = hkdf_expand(key_material, length=80, hash=hashlib.sha256)
    if not Hmac(sharedSecretExpanded[32:64]).is_valid(secret[:32] + secret[64:], expected=secret[32:64]):
        raise ValueError('Hmac validation failed')

    keysEncrypted = sharedSecretExpanded[64:] + secret[64:]
    keysDecrypted = Aes(sharedSecretExpanded[:32]).decrypt(keysEncrypted)

    encKey = keysDecrypted[:32]
    macKey = keysDecrypted[32:64]

    return encKey, macKey

class Hmac(object):

    def __init__(self, mac_key):
        self._mac_key = mac_key

    def hash(self, data):
        return hmac.new(self._mac_key, data, digestmod=hashlib.sha256).digest()

    def is_valid(self, data, expected=None):
        if expected is None:
            return self.hash(data[32:]) == data[:32]
        return self.hash(data) == expected

class Aes(object):

    def __init__(self, enc_key):
        self._enc_key = enc_key

    def pad(self, s):
        bs = AES.block_size
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs).encode()

    def unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]

    def encrypt(self, plainbits):
        plainbits = self.pad(plainbits)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self._enc_key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(plainbits)

    def decrypt(self, cipherbits):
        iv = cipherbits[:AES.block_size]
        cipher = AES.new(self._enc_key, AES.MODE_CBC, iv)
        plainbits = cipher.decrypt(cipherbits[AES.block_size:])
        return self.unpad(plainbits)
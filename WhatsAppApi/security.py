import hmac
import hashlib

class Hmac(object):

    def __init__(self, mac_key):
        self._mac_key = mac_key

    def hash(self, data):
        return hmac.new(self._mac_key, data, digestmod=hashlib.sha256).digest()

    def is_valid(self, data):
        return self.hash(data[32:]) == data[:32]
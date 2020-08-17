import websocket

import re
import requests

import time
import threading

import json
import base64, os

import hashlib
import hmac
from hkdf import hkdf_expand

from Crypto import Random
from Crypto.Cipher import AES

import curve25519
from .qrcode import render_qrcode, gen_qrcode

from enum import Enum, unique

def wait_until(somepredicate, timeout, period=0.05, *args, **kwargs):
    mustend = time.time() + timeout
    while time.time() < mustend:
        if somepredicate(*args, **kwargs):
            return True
        time.sleep(period)
    return False

def get_whatsappweb_version():
    url = 'https://web.whatsapp.com/'
    headers = {'User-Agent':'Mozilla/75 Gecko/20100101 Firefox/76'}

    result = requests.get(url, headers=headers)
    m = re.search(r'l=\"([0-9]+)\.([0-9]+)\.([0-9]+)\"', result.text)
    if m is None:
        raise Exception('Can\'t find WhatsAppWeb version')
    return [int(m.group(1)), int(m.group(2)), int(m.group(3))]

def HmacSha256(secret, message):
    return hmac.new(secret, message, digestmod=hashlib.sha256).digest()

def AESEncrypt(key, plainbits):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(plainbits)

def AESDecrypt(key, cipherbits):
    iv = cipherbits[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(cipherbits[AES.block_size:])

@unique
class State(Enum):
    OPENING = 0
    OPEN = 1
    CLOSED = 2

class Client(object):

    whatsapp_wss_url = 'wss://web.whatsapp.com/ws'
    origin_url = 'https://web.whatsapp.com'
    default_save_session_path = 'default.session'

    def __init__(self,
        debug=False, enable_trace=False, trace_truncate=1000,
        timeout=10,
        restore_sessions=False,
        **kwargs):

        self._debug = debug
        self._enable_trace = enable_trace
        self._trace_truncate = trace_truncate
        self._state = State.OPENING

        self._timeout = timeout
        self._restore_sessions = restore_sessions

        self._on_open = kwargs.get('on_open')
        self._on_close = kwargs.get('on_close')

        self._long_browser_desc = kwargs.get('long_browser_desc', 'Python Whatsapp Client')
        self._short_browser_desc = kwargs.get('short_browser_desc', 'Whatsapp Client')
        self._browser_desc = [self._long_browser_desc, self._short_browser_desc]

        self._received_msgs = {}
        self._ws = websocket.WebSocketApp(Client.whatsapp_wss_url,
            on_message = lambda ws, msg: self.__on_message(ws, msg),
            on_error = lambda ws, err: self.__on_error(ws, err),
            on_close = lambda ws: self.__on_close(ws),
            on_open = lambda ws: self.__on_open(ws)
        )

        self._ws_thread = threading.Thread(target=self._ws.run_forever, kwargs={'origin': Client.origin_url})
        self._ws_thread.daemon = True
        self._ws_thread.start()
        
        if wait_until(lambda self: self._state == State.OPEN or self._state == State.CLOSED, self._timeout, self=self) == False:
            raise Exception('Websocket timed out')
        if self._state == State.CLOSED:
            raise Exception('Cannot open websocket')

        self.login()

    def login(self):
        self._clientId = str(base64.b64encode(os.urandom(16)), 'utf8')
        self._whatsappweb_version = get_whatsappweb_version()

        connection_query_name = 'connection_query'
        connection_query_json = ['admin', 'init', self._whatsappweb_version, self._browser_desc, self._clientId, True]
        self.__send(connection_query_name, connection_query_json)
        connection_result = self.wait_query_pop_json(connection_query_name)

        if connection_result['status'] != 200:
            raise Exception('Websocket connection refused')
        
        self._qrcode = {
            'must_scan': False,
            'id': 0,
            'ref': connection_result['ref'],
            'ttl' : connection_result['ttl'] / 1000 - 1,
            'time' : connection_result['time']}
        self._qrcode['timeout'] = time.time() + self._qrcode['ttl']

        if self._restore_sessions and os.path.exists(Client.default_save_session_path):
            self.restore_session()
        else:
            self._qrcode['must_scan'] = True
            self._privateKey = curve25519.Private()
            self._publicKey = self._privateKey.get_public()

            bin_qrcode = gen_qrcode(self._qrcode['ref'], self._publicKey, self._clientId)
            self._qrcode['qrcode'] = render_qrcode(bin_qrcode)

    def load_s1234_queries(self):
        try:
            conn_result = self.wait_json_pop_json('Conn')
            blocklist_result = self.wait_json_pop_json('Blocklist')
            stream_result = self.wait_json_pop_json('Stream')
            props_result = self.wait_json_pop_json('Props')
        except Exception:
            return False
        self._conn = conn_result[1]
        self._blocklist = blocklist_result[1]
        self._stream = stream_result[1]
        self._props = props_result[1]
        return True

    def restore_session(self):
        session_data = self.load_session(Client.default_save_session_path)
        if session_data is None:
            raise Exception('Invalid session data')
        self._clientId = session_data['clientId']
        restore_query_name = 'restore_query'
        restore_query_json = ['admin', 'login', session_data['clientToken'], session_data['serverToken'], self._clientId, 'takeover']
        self.__send(restore_query_name, restore_query_json)
        restore_result = self.wait_query_pop_json(restore_query_name)

        if restore_result['status'] == 401:
            raise Exception('Unpaired from the phone')
        if restore_result['status'] == 403:
            raise Exception('Access denied')
        if restore_result['status'] == 405:
            raise Exception('Already logged in')
        if restore_result['status'] == 409:
            raise Exception('Logged in from another location')
        if restore_result['status'] != 200:
            raise Exception('Restore session refused')

        if self.load_s1234_queries() == False:
            # Resolving challenge
            raise Exception('Query timed out')

        if self._restore_sessions:
            self.save_session(Client.default_save_session_path)
        if self._debug:
            print('Session restored')

    def regen_qrcode(self):
        self._qrcode['id'] += 1

        new_qrcode_query_name = '{}.{}'.format('new_qrcode_query', '--{}'.format(self._qrcode['id']))
        new_qrcode_query_json = ["admin","Conn","reref"]
        self.__send(new_qrcode_query_name, new_qrcode_query_json)
        new_qrcode_result = self.wait_query_pop_json(new_qrcode_query_name)

        if new_qrcode_result['status'] != 200:
            raise Exception('Websocket connection refused')
        self._qrcode['ref'] = new_qrcode_result['ref']
        self._qrcode['timeout'] = time.time() + self._qrcode['ttl']

        bin_qrcode = gen_qrcode(self._qrcode['ref'], self._publicKey, self._clientId)
        self._qrcode['qrcode'] = render_qrcode(bin_qrcode)

        if self._debug:
            print('QRCode regenerated')

    def qrcode_ready_to_scan(self):
        if self.load_s1234_queries() == False:
            self.regen_qrcode()
            return False

        if self._restore_sessions:
            self.save_session(Client.default_save_session_path)
        self._qrcode['must_scan'] = False

        if self._debug:
            print('QRCode scanned')
        self.generate_keys()
        return True

    def generate_keys(self):
        secret = base64.b64decode(self._conn['secret'])
        if len(secret) != 144:
            raise Exception('Invalid secret')

        sharedSecret = self._privateKey.get_shared_key(curve25519.Public(secret[:32]), lambda a:a)

        key_material = HmacSha256(('\0' * 32).encode('utf8'), sharedSecret)
        sharedSecretExpanded = hkdf_expand(key_material, length=80, hash=hashlib.sha256)
        if HmacSha256(sharedSecretExpanded[32:64], secret[:32] + secret[64:]) != secret[32:64]:
            raise Exception('Login aborted')

        keysEncrypted = sharedSecretExpanded[64:] + secret[64:]
        keysDecrypted = AESDecrypt(sharedSecretExpanded[:32], keysEncrypted)

        self._encKey = keysDecrypted[:32]
        self._macKey = keysDecrypted[32:64]

        if self._debug:
            print('Keys generated')

    def load_session(self, session_path):
        f = open(session_path, 'r')
        data = f.read()
        f.close()
        session_data = json.loads(data)
        if 'clientId' not in session_data or 'serverToken' not in session_data or 'clientToken' not in session_data:
            return None
        if self._debug:
            print('Session loaded')
        return(session_data)

    def save_session(self, session_path):
        session_data = {
            'clientId':self._clientId,
            'serverToken':self._conn['serverToken'],
            'clientToken':self._conn['clientToken']}
        f = open(session_path, 'w')
        f.write(json.dumps(session_data))
        f.close()
        if self._debug:
            print('Session saved')

    def logout(self):
        loggout_query_name = 'goodbye,'
        loggout_query_json = ["admin","Conn","disconnect"]
        self.__send(loggout_query_name, loggout_query_json)
        self._ws.close()

    def __send(self, messageTag, payload):
        msg = messageTag + ','
        if type(payload) in (dict, list):
            msg += json.dumps(payload)
        else:
            msg += payload
        if self._enable_trace:
            if len(msg) > self._trace_truncate:
                print('Send: {}'.format(msg[0:self._trace_truncate] + '...'))
            else:
                print('Send: {}'.format(msg))
        self._ws.send(msg)

    def find_json_in_received_msgs(self, json_name):
        for key in self._received_msgs.keys():
            msg = self._received_msgs[key]
            if 'json' in msg:
                if json_name in msg['json']:
                    return key
        return None

    def wait_json(self, json_name):
        if wait_until(lambda self: self.find_json_in_received_msgs(json_name) != None, self._timeout, self=self) == False:
            raise Exception('Receive message timed out')

    def wait_json_pop_data(self, json_name):
        self.wait_json(json_name)
        key = self.find_json_in_received_msgs(json_name)
        return self._received_msgs.pop(key)['data']

    def wait_json_pop_json(self, json_name):
        self.wait_json(json_name)
        key = self.find_json_in_received_msgs(json_name)
        return self._received_msgs.pop(key)['json']

    def wait_query(self, query_name):
        if wait_until(lambda self: query_name in self._received_msgs, self._timeout, self=self) == False:
            raise Exception('Receive message timed out')

    def wait_query_pop_data(self, query_name):
        self.wait_query(query_name)
        return self._received_msgs.pop(query_name)['data']

    def wait_query_pop_json(self, query_name):
        self.wait_query(query_name)
        return self._received_msgs.pop(query_name)['json']

    def __on_message(self, ws, msg):
        if self._enable_trace:
            if len(msg) > self._trace_truncate:
                print('Recv: {}'.format(msg[0:self._trace_truncate] + '...'))
            else:
                print('Recv: {}'.format(msg))

        messageTag = msg.split(',')[0]

        msg_data = {'data': msg[len(messageTag) + 1:]}
        try: msg_data['json'] = json.loads(msg_data['data'])
        except ValueError: pass

        self._received_msgs[messageTag] = msg_data

    def __on_error(self, ws, err):
        print(err)

    def __on_close(self, ws):
        self._state = State.CLOSED
        if self._debug:
            print("Websocket disconnected")
        self.callback(self._on_close)

    def __on_open(self, ws):
        self._state = State.OPEN
        if self._debug:
            print('Websocket opened')
        self.callback(self._on_open)

    def callback(self, callback, *args):
        if callback:
            try:
                callback(self, *args)
            except Exception as e:
                if self._debug:
                    print("error from callback {}: {}".format(callback, e))

    def must_scan_qrcode(self):
        return self._qrcode['must_scan']

    def get_qrcode(self):
        return self._qrcode['qrcode']
                    
    def get_pushname(self):
        return self._conn['pushname']

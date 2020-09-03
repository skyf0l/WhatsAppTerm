import websocket

import re
import requests

import time
import threading

import json
import os

import binascii
from base64 import b64encode, b64decode

import curve25519
from .qrcode import render_qrcode, gen_qrcode

from enum import Enum, unique

from .defines import WebMessage, Metrics
from .binary_reader import read_binary
from .binary_writer import write_binary

from .security import Aes, Hmac
from .security import get_enc_mac_keys

from .session import load_session, save_session

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
        raise ValueError('Can\'t find WhatsAppWeb version')
    return [int(m.group(1)), int(m.group(2)), int(m.group(3))]

def getTimestamp():
    return int(time.time());

@unique
class State(Enum):
    OPENING = 0
    OPEN = 1
    CLOSED = 2

class Client(object):

    # constants
    whatsapp_wss_url = 'wss://web.whatsapp.com/ws'
    origin_url = 'https://web.whatsapp.com'
    default_save_session_path = 'default.session'

    # vars
    _nb_msg_sent = 0
    _received_msgs = {}

    def __init__(self,
        debug=False, enable_trace=False, trace_truncate=100,
        timeout=10,
        restore_sessions=False,
        on_open=None, on_close=None,
        long_browser_desc='Python Whatsapp Client', short_browser_desc='Whatsapp Client'):

        self._debug = debug
        self._enable_trace = enable_trace
        self._trace_truncate = trace_truncate
        self._state = State.OPENING

        self._timeout = timeout
        self._restore_sessions = restore_sessions

        self._on_open = on_open
        self._on_close = on_close

        self._long_browser_desc = long_browser_desc
        self._short_browser_desc = short_browser_desc
        self._browser_desc = [self._long_browser_desc, self._short_browser_desc]
        import ssl
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
            raise TimeoutError('Websocket timed out')
        if self._state == State.CLOSED:
            raise ConnectionRefusedError('Cannot open websocket')

        self.login()

    def login(self):
        self._clientId = str(b64encode(os.urandom(16)), 'utf8')
        self._whatsappweb_version = get_whatsappweb_version()

        connection_query_name = 'connection_query'
        connection_query_json = ['admin', 'init', self._whatsappweb_version, self._browser_desc, self._clientId, True]
        self.__send(connection_query_name, connection_query_json)
        connection_result = self.wait_query_pop_json(connection_query_name)

        if connection_result['status'] != 200:
            raise ConnectionRefusedError('Websocket connection refused')
        
        self._qrcode = {
            'must_scan': False,
            'id': 0,
            'ref': connection_result['ref'],
            'ttl' : connection_result['ttl'] / 1000 - 1,
            'time' : connection_result['time']}
        self._qrcode['timeout'] = time.time() + self._qrcode['ttl']

        if self._restore_sessions and os.path.exists(Client.default_save_session_path):
            self.restore_session()
            self.post_login()
        else:
            self._qrcode['must_scan'] = True
            self._privateKey = curve25519.Private()
            self._publicKey = self._privateKey.get_public()

            bin_qrcode = gen_qrcode(self._qrcode['ref'], self._publicKey, self._clientId)
            self._qrcode['qrcode'] = render_qrcode(bin_qrcode)

    def load_s1234_queries(self):
        try:
            conn_result = self.wait_json_pop_json('Conn')[1]
            blocklist_result = self.wait_json_pop_json('Blocklist')[1]
            stream_result = self.wait_json_pop_json('Stream')[1]
            props_result = self.wait_json_pop_json('Props')[1]
        except TimeoutError:
            return False
        self._conn = conn_result
        self._blocklist = blocklist_result
        self._stream = stream_result
        self._props = props_result

        self._clientToken = self._conn['clientToken']
        self._serverToken = self._conn['serverToken']
        return True

    def restore_session(self):
        session_data = load_session(Client.default_save_session_path)
        if session_data is None:
            raise ValueError('Invalid session data')
        self._clientId = session_data['clientId']
        self._clientToken = session_data['clientToken']
        self._serverToken = session_data['serverToken']
        self._encKey = session_data['encKey']
        self._macKey = session_data['macKey']

        self._aes = Aes(self._encKey)
        self._hmac = Hmac(self._macKey)

        restore_query_name = 'restore_query'
        restore_query_json = ['admin', 'login', self._clientToken, self._serverToken, self._clientId, 'takeover']
        self.__send(restore_query_name, restore_query_json)

        # return error or challenge
        if wait_until(lambda self: restore_query_name in self._received_msgs or self.find_json_in_received_msgs('Cmd') != None, self._timeout, self=self) == False:
            raise TimeoutError('Receive message timed out')

        if self.find_json_in_received_msgs('Cmd') != None:
            self.resolve_challenge()

        restore_result = self.wait_query_pop_json(restore_query_name)
        if restore_result['status'] == 401:
            raise ConnectionRefusedError('Unpaired from the phone')
        if restore_result['status'] == 403:
            raise ConnectionRefusedError('Access denied')
        if restore_result['status'] == 405:
            raise ConnectionRefusedError('Already logged in')
        if restore_result['status'] == 409:
            raise ConnectionRefusedError('Logged in from another location')
        if restore_result['status'] != 200:
            raise ConnectionRefusedError('Restore session refused')

        if self.load_s1234_queries() == False:
            raise TimeoutError('Query timed out')

        if self._restore_sessions:
            save_session(self, Client.default_save_session_path)
            if self._debug:
                print('Session saved')
        if self._debug:
            print('Session restored')

    def resolve_challenge(self):
        cmd_result = self.wait_json_pop_json('Cmd')[1]
        if cmd_result['type'] != 'challenge':
            raise Exception('Challenge expected')

        challenge = b64decode(cmd_result['challenge'])
        signed_challenge = self._hmac.hash(challenge)

        challenge_query_name = 'challenge'
        challenge_query_json = ['admin', 'challenge', str(b64encode(signed_challenge), 'utf8'), self._serverToken, self._clientId]
        self.__send(challenge_query_name, challenge_query_json)
        challenge_result = self.wait_query_pop_json(challenge_query_name)

        if challenge_result['status'] != 200:
            raise ConnectionRefusedError('Challenge refused')

    def regen_qrcode(self):
        self._qrcode['id'] += 1

        new_qrcode_query_name = '{}.{}'.format('new_qrcode_query', '--{}'.format(self._qrcode['id']))
        new_qrcode_query_json = ['admin', 'Conn', 'reref']
        self.__send(new_qrcode_query_name, new_qrcode_query_json)
        new_qrcode_result = self.wait_query_pop_json(new_qrcode_query_name)

        if new_qrcode_result['status'] != 200:
            raise ConnectionRefusedError('Websocket connection refused')
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

        if self._debug:
            print('QRCode scanned')

        self.generate_keys()

        if self._restore_sessions:
            save_session(self, Client.default_save_session_path)
            if self._debug:
                print('Session saved')
        self._qrcode['must_scan'] = False

        self.post_login()
        return True

    def generate_keys(self):
        self._encKey, self._macKey = get_enc_mac_keys(self._conn['secret'], self._privateKey)

        self._aes = Aes(self._encKey)
        self._hmac = Hmac(self._macKey)

        if self._debug:
            print('Keys generated')

    def post_login(self):
        pass

    def send_text_message(self, number, text):
        # in work
        messageId = '3EB0' + str(binascii.hexlify(Random.get_random_bytes(8)).upper(), 'utf8')

        messageParams = {'key': {'fromMe': True, 'remoteJid': number + '@s.whatsapp.net', 'id': messageId},'messageTimestamp': getTimestamp(), 'status': 1, 'message': {'conversation': text}}
        msgData = ['action', {'type': 'relay', 'epoch': str(self.messageSentCount)},[['message', None, WebMessage.encode(messageParams)]]]
        encryptedMessage = self.encrypt_msg(write_binary(msgData))
        payload = b'\x10\x80' + encryptedMessage

        self.__send(messageId, payload)
        self._nb_msg_sent += 1

    # close session -> must to rescan the qrcode
    def logout(self):
        loggout_query_name = 'goodbye'
        loggout_query_json = ['admin','Conn','disconnect']
        self.__send(loggout_query_name + ',', loggout_query_json)
        self.wait_query(loggout_query_name)
        self._ws.close()

    def __send(self, messageTag, payload):
        msg = messageTag + ','
        if type(payload) in (dict, list):
            msg += json.dumps(payload)
        elif type(payload) is bytes:
            msg = msg.encode() + payload
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
            raise TimeoutError('Receive message timed out')

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
            raise TimeoutError('Receive message timed out')

    def wait_query_pop_data(self, query_name):
        self.wait_query(query_name)
        return self._received_msgs.pop(query_name)['data']

    def wait_query_pop_json(self, query_name):
        self.wait_query(query_name)
        return self._received_msgs.pop(query_name)['json']

    def wait_one_msg(self):
        if wait_until(lambda self: len(self._received_msgs) > 0, self._timeout, self=self) == False:
            raise TimeoutError('Receive message timed out')
        return next(iter(self._received_msgs))

    def __on_message(self, ws, msg):
        if isinstance(msg, bytes):
            messageTag = str(msg.split(b',')[0], 'utf8')
            msg_data = {'data': msg[len(messageTag) + 1:]}
            msg_data['json'] = self.decrypt_msg(msg_data['data'])
            msg_data['data'] = 'OK'
        else:
            messageTag = msg.split(',')[0]
            msg_data = {'data': msg[len(messageTag) + 1:]}
            try:
                msg_data['json'] = json.loads(msg_data['data'])
                msg_data['data'] = 'OK'
            except ValueError:
                pass

        if self._enable_trace:
            json_msg = str(msg_data['json'])
            if len(json_msg) <= self._trace_truncate or self._trace_truncate <= 0:
                print('Recv: {},{}'.format(messageTag, json_msg))
            else:
                print('Recv: {},{}'.format(messageTag, json_msg[0:self._trace_truncate] + '...'))

        self._received_msgs[messageTag] = msg_data

    def decrypt_msg(self, data):
        if self._hmac.is_valid(data) != True:
            return None
        binary_data = self._aes.decrypt(data[32:])
        data = read_binary(binary_data, withMessages=True)
        return data

    def encrypt_msg(self, msg):
        enc = self._aes.encrypt(msg)
        return self._hmac.hash(enc) + enc; 

    def __on_error(self, ws, err):
        print(err)

    def __on_close(self, ws):
        self._state = State.CLOSED
        if self._debug:
            print('Websocket disconnected')
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
                    print('error from callback {}: {}'.format(callback, e))

    def must_scan_qrcode(self):
        return self._qrcode['must_scan']

    def get_qrcode(self):
        return self._qrcode['qrcode']
                    
    def get_pushname(self):
        return self._conn['pushname']

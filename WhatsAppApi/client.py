import time

import json
import os
import sys

import binascii
from base64 import b64encode, b64decode

import curve25519

from .BinaryMessages.binary_reader import read_binary
from .BinaryMessages.binary_writer import write_binary

from .defines import *
from .utilities import *
from .security import *

from .Client.client_websocket import ClientWebSocket
from .Client.client_qrcode import ClientQRCode, gen_qrcode, render_qrcode
from .Client.client_session import ClientSession
from .Client.client_chats import ClientChats
from .Client.client_messages import ClientMessages
from .Client.client_contacts import ClientContacts
from .Client.client_payload_action import ClientPayloadAction

class Client(ClientWebSocket,
    ClientQRCode,
    ClientSession,
    ClientChats, ClientMessages, ClientContacts,
    ClientPayloadAction):

    # constants
    default_save_session_path = 'default.session'

    # msgs
    _nb_msg_sent = 0
    _received_msgs = {}
    _expected_message_tags = []

    # chats
    _frequent_contacts = []
    _frequent_contacts_loaded = False
    _contacts = {}
    _contacts_loaded = False
    _chats = []
    _chats_loaded = False
    _chats_messages = {}

    # other
    _battery = {
        'value': 100,
        'live': False,
        'powersave': False
    }

    def __init__(self,
        debug=False, enable_trace=False, trace_truncate=100,
        timeout=10,
        session_path=None,
        on_open=None, on_close=None,
        long_browser_desc='Python Whatsapp Client', short_browser_desc='Whatsapp Client'):

        self._debug = debug
        self._enable_trace = enable_trace
        self._trace_truncate = trace_truncate
        self._state = State.OPENING

        self._timeout = timeout
        self._session_path = session_path

        self._on_open = on_open
        self._on_close = on_close

        self._long_browser_desc = long_browser_desc
        self._short_browser_desc = short_browser_desc
        self._browser_desc = [self._long_browser_desc, self._short_browser_desc]

        self.open_websocket()

        if wait_until(lambda self: self._state == State.OPEN or self._state == State.CLOSED, self._timeout, self=self) == False:
            raise TimeoutError('Websocket timed out')
        if self._state == State.CLOSED:
            raise ConnectionRefusedError('Cannot open websocket')

        self.login()

    def login(self):
        self._expected_message_tags = ['s1', 's2', 's3', 's4']

        self._clientId = str(b64encode(os.urandom(16)), 'utf8')
        self._whatsappweb_version = get_whatsappweb_version()

        connection_query_name = 'connection_query'
        self._expected_message_tags.append(connection_query_name)
        connection_query_json = ['admin', 'init', self._whatsappweb_version, self._browser_desc, self._clientId, True]
        self.ws_send(connection_query_name, connection_query_json)
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

        if self._session_path and os.path.exists(self._session_path):
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

        self._battery['value'] = self._conn['battery']
        self._battery['live'] = self._conn['plugged']
        return True

    def generate_keys(self):
        self._encKey, self._macKey = get_enc_mac_keys(self._conn['secret'], self._privateKey)

        self._aes = Aes(self._encKey)
        self._hmac = Hmac(self._macKey)

        if self._debug:
            print('Keys generated')

    def post_login(self):
        self.run_presence_loop()

    def send_text_message(self, number, text):
        # in work
        messageId = '3EB0' + str(binascii.hexlify(Random.get_random_bytes(8)).upper(), 'utf8')

        messageParams = {'key': {'fromMe': True, 'remoteJid': number + '@s.whatsapp.net', 'id': messageId},'messageTimestamp': get_timestamp(), 'status': 1, 'message': {'conversation': text}}
        msgData = ['action', {'type': 'relay', 'epoch': str(self._nb_msg_sent)},[['message', None, WebMessage.encode(messageParams)]]]
        encryptedMessage = self.encrypt_msg(write_binary(msgData))
        payload = b'\x10\x80' + encryptedMessage

        self.ws_send(messageId, payload)
        self._nb_msg_sent += 1

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

    def decrypt_msg(self, data):
        if wait_until(lambda self: hasattr(self, '_hmac'), self._timeout, self=self) == False:
            raise TimeoutError('Generating key timed out')

        if self._hmac.is_valid(data) != True:
            return None
        binary_data = self._aes.decrypt(data[32:])
        data = read_binary(binary_data, withMessages=True)
        return data

    def encrypt_msg(self, msg):
        enc = self._aes.encrypt(msg)
        return self._hmac.hash(enc) + enc; 

    def get_messages(self, jid):
        if jid not in self._chats_messages:
            return None
        return self._chats_messages[jid]
                    
    def get_pushname(self):
        return self._conn['pushname']

import websocket

import time
import threading

import json
import os
import sys

import binascii
from base64 import b64encode, b64decode

import curve25519
from .qrcode import render_qrcode, gen_qrcode

from enum import Enum, unique

from .binary_reader import read_binary
from .binary_writer import write_binary

from .defines import *
from .utilities import *
from .security import *

from .session import load_session, save_session

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

    # msgs
    _nb_msg_sent = 0
    _received_msgs = {}
    _expected_message_tags = []

    # chats
    _frequent_contacts_loaded = False
    _frequent_contacts = []
    _chats_loaded = False
    _chats = []
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
        restore_sessions=False,
        on_open=None, on_close=None,
        long_browser_desc='Python Whatsapp Client', short_browser_desc='Whatsapp Client'):
        #websocket.enableTrace(True)

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

        self._ws = websocket.WebSocketApp(Client.whatsapp_wss_url,
            on_message = lambda ws, msg: self.__on_message(ws, msg),
            on_error = lambda ws, err: self.__on_error(ws, err),
            on_close = lambda ws: self.__on_close(ws),
            on_open = lambda ws: self.__on_open(ws)
        )

        self._ws_thread = threading.Thread(target=self._ws.run_forever, kwargs={'origin': Client.origin_url})
        self._ws_thread.daemon = True
        self._ws_thread.start()
        
        self._expected_message_tags = ['s1', 's2', 's3', 's4']

        if wait_until(lambda self: self._state == State.OPEN or self._state == State.CLOSED, self._timeout, self=self) == False:
            raise TimeoutError('Websocket timed out')
        if self._state == State.CLOSED:
            raise ConnectionRefusedError('Cannot open websocket')

        self.login()

    def login(self):
        self._clientId = str(b64encode(os.urandom(16)), 'utf8')
        self._whatsappweb_version = get_whatsappweb_version()

        connection_query_name = 'connection_query'
        self._expected_message_tags.append(connection_query_name)
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

        self._battery['value'] = self._conn['battery']
        self._battery['live'] = self._conn['plugged']
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
        self._expected_message_tags.append(restore_query_name)
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
        self._expected_message_tags.append(challenge_query_name)
        challenge_query_json = ['admin', 'challenge', str(b64encode(signed_challenge), 'utf8'), self._serverToken, self._clientId]
        self.__send(challenge_query_name, challenge_query_json)
        challenge_result = self.wait_query_pop_json(challenge_query_name)

        if challenge_result['status'] != 200:
            raise ConnectionRefusedError('Challenge refused')

    def regen_qrcode(self):
        self._qrcode['id'] += 1

        new_qrcode_query_name = '{}.{}'.format('new_qrcode_query', '--{}'.format(self._qrcode['id']))
        self._expected_message_tags.append(new_qrcode_query_name)
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
        self.run_presence_loop()

    def presence_loop(self):
        time.sleep(15)
        while self._state == State.OPEN:
            self._ws.send('?,,')
            time.sleep(30)

    def run_presence_loop(self):
        self._presence_thread = threading.Thread(target=self.presence_loop)
        self._presence_thread.daemon = True
        self._presence_thread.start()

    def set_battery(self, battery):
        self._battery['value'] = battery['value']
        self._battery['live'] = battery['live'] == 'true'
        self._battery['powersave'] = battery['powersave'] == 'true'

    def add_message(self, message):
        try:
            jid = message['key']['remoteJid'].replace('s.whatsapp.net', 'c.us')
            if jid not in self._chats_messages:
                self._chats_messages[jid] = []

            msg = {
                'id': message['key']['id'],
                'from_me': message['key']['fromMe'],
                'at': int(message['messageTimestamp']),
                'message': {
                    'type': MessageType.get(list(message['message'].keys())[0]) if 'message' in message else MessageType.NoMessage,
                    'text': None,
                    'content': None
                },
                'participant' : message['participant'] if 'participant' in message else None,
                'message_stub' : MessageStubType.get(message['messageStubType']) if 'messageStubType' in message else MessageStubType.Unknown,
                'message_stub_parameters' : message['messageStubParameters'] if 'messageStubParameters' in message else None,
                'status': MessageStatus.Error if 'status' not in message else MessageStatus.get(message['status'])
            }

            if msg['message']['type'] != MessageType.NoMessage:
                message_content = message['message'][list(message['message'].keys())[0]]
                if msg['message']['type'] == MessageType.Conversation:
                    msg['message']['text'] = message_content
                elif msg['message']['type'] == MessageType.ExtendedTextMessage:
                    msg['message']['text'] = message_content['text']
                elif msg['message']['type'] == MessageType.ImageMessage:
                    if 'caption' in message_content:
                        msg['message']['text'] = message_content['caption']
                elif msg['message']['type'] == MessageType.VideoMessage:
                    if 'caption' in message_content:
                        msg['message']['text'] = message_content['caption']
                elif msg['message']['type'] == MessageType.AudioMessage:
                    pass
                elif msg['message']['type'] == MessageType.StickerMessage:
                    pass
                else:
                    eprint_report('Unknown message type: {}'.format(message))

            self._chats_messages[jid].append(msg)
        except Exception as e:
            eprint_report('Invalid chat message: {}'.format(message), add_traceback=True)

    def add_messages(self, messages):
        for message in messages:
            self.add_message(message)

    def action(self, action):
        if action[1] == None:
            content = action[2][0]
            if content[0] == 'battery':
                battery = content[1]
                self.set_battery(battery)
                return True
            elif content[0] == 'contacts':
                if 'type' in content[1] and content[1]['type'] == 'frequent':
                    contacts = content[2]
                    for contact in contacts:
                        frequent_contact = {
                            'jid': contact[1]['jid'],
                            'type': contact[0]
                        }
                        self._frequent_contacts.append(frequent_contact)
                    return True

        elif 'add' in action[1]:
            if action[1]['add'] == 'last':
                messages = action[2]
                self.add_messages(messages)
                return True
            elif action[1]['add'] == 'before':
                if 'last' in action[1] and action[1]['last'] == 'true':
                    messages = action[2]
                    self.add_messages(messages)
                    return True
            elif action[1]['add'] == 'relay':
                messages = action[2]
                self.add_messages(messages)
                return True
            elif action[1]['add'] == 'update':
                messages = action[2]
                self.add_messages(messages)
                return True

        return False

    def is_in_chats(self, jid):
        for chat in self._chats:
            if chat['jid'] == jid:
                return True
        return False

    def add_chat(self, chat):
        try:
            if not self.is_in_chats(chat['jid']):
                new_chat = {
                    'jid': chat['jid'],
                    'not_read_count': int(chat['count']),
                    'total_count': 0,
                    'name': str(chat['name'], 'utf8') if 'name' in chat else None,
                    't': int(chat['t']),
                    'mute': int(chat['mute']),
                    'modify_tag': chat['modify_tag'] if 'modify_tag' in chat else None,
                    'spam': chat['spam'] == 'true' if 'spam' in chat else None,
                    'status': UserStatus.Unknown,
                    'status_at': 0
                }
                self._chats.append(new_chat)
        except Exception as e:
            eprint_report('Invalid chat data: {}'.format(chat), add_traceback=True)

    def order_chats(self):
        self._chats.sort(key=lambda chat: chat['t'], reverse=True)
        
    def add_chats(self, chats):
        for chat in chats:
            if len(chat) == 3 and chat[0] == 'chat' and chat[2] == None:
                self.add_chat(chat[1])
            else:
                eprint_report('Unknown chat format: {}'.format(chat))
        self.order_chats()
        self._chats_loaded = True

    def response(self, action):
        if 'type' in action[1] and action[1]['type'] == 'chat':
            self.add_chats(action[2])
            return True

        if 'type' in action[1] and action[1]['type'] == 'contacts':
            return True

        return False

    def send_text_message(self, number, text):
        # in work
        messageId = '3EB0' + str(binascii.hexlify(Random.get_random_bytes(8)).upper(), 'utf8')

        messageParams = {'key': {'fromMe': True, 'remoteJid': number + '@s.whatsapp.net', 'id': messageId},'messageTimestamp': get_timestamp(), 'status': 1, 'message': {'conversation': text}}
        msgData = ['action', {'type': 'relay', 'epoch': str(self._nb_msg_sent)},[['message', None, WebMessage.encode(messageParams)]]]
        encryptedMessage = self.encrypt_msg(write_binary(msgData))
        payload = b'\x10\x80' + encryptedMessage

        self.__send(messageId, payload)
        self._nb_msg_sent += 1

    # close session -> must to rescan the qrcode
    def logout(self):
        loggout_query_name = 'goodbye'
        self._expected_message_tags.append(loggout_query_name)
        loggout_query_json = ['admin','Conn','disconnect']
        self.__send(loggout_query_name + ',', loggout_query_json)
        self.wait_query(loggout_query_name)
        self._ws.close()

    def __send(self, message_tag, payload):
        msg = message_tag + ','
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
        try:

            if msg[0] == '!' and ',' not in msg:
                # presential msg
                return

            if isinstance(msg, bytes):
                message_tag = str(msg.split(b',')[0], 'utf8')
                msg_data = {'data': msg[len(message_tag) + 1:]}
                msg_data['json'] = self.decrypt_msg(msg_data['data'])
                msg_data['data'] = 'OK'
            else:
                message_tag = msg.split(',')[0]
                msg_data = {'data': msg[len(message_tag) + 1:]}
                try:
                    msg_data['json'] = json.loads(msg_data['data'])
                    msg_data['data'] = 'OK'
                except ValueError:
                    pass

            if self._enable_trace:
                trace_data_msg = str(msg_data['json'] if 'json' in msg_data else msg_data['data'])
                if len(trace_data_msg) == 0:
                    trace_msg = message_tag
                elif len(trace_data_msg) <= self._trace_truncate:
                    trace_msg = '{},{}'.format(message_tag, trace_data_msg)
                else:
                    trace_msg = '{},{}...'.format(message_tag, trace_data_msg[0:self._trace_truncate])
                print('Recv: {}'.format(trace_msg))

            if message_tag in self._expected_message_tags:
                self._expected_message_tags.remove(message_tag)
                self._received_msgs[message_tag] = msg_data
                return

            if 'json' in msg_data and type(msg_data['json']) is list and len(msg_data['json']) == 3:
                if msg_data['json'][0] == 'action':
                    if not self.action(msg_data['json']):
                        print_unknown_msg(message_tag, msg_data)
                elif msg_data['json'][0] == 'response':
                    if not self.response(msg_data['json']):
                        print_unknown_msg(message_tag, msg_data)
                else:
                    print_unknown_msg(message_tag, msg_data)
                    self._received_msgs[message_tag] = msg_data
            else:
                print_unknown_msg(message_tag, msg_data)
                self._received_msgs[message_tag] = msg_data
        except Exception as e:
            eprint_report('Invalid msg: {},({}){}'.format(message_tag, 'json' if 'json' in msg_data else 'data', msg_data['json'] if 'json' in msg_data else msg_data['data']), add_traceback=True)

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

    def get_chats(self):
        if wait_until(lambda self: self._chats_loaded == True, self._timeout, self=self) == False:
            raise TimeoutError('Receive chats timed out')
        return self._chats

    def get_messages(self, jid):
        if jid not in self._chats_messages:
            return None
        return self._chats_messages[jid]
                    
    def get_pushname(self):
        return self._conn['pushname']

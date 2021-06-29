import websocket

import threading
import time

import json

from ..utilities import *
from ..defines import State

class ClientWebSocket():

    # constants
    whatsapp_wss_url = 'wss://web.whatsapp.com/ws'
    origin_url = 'https://web.whatsapp.com'

    def open_websocket(self):
        #websocket.enableTrace(True)

        self._ws = websocket.WebSocketApp(ClientWebSocket.whatsapp_wss_url,
            on_message = lambda ws, msg: self.__on_message(ws, msg),
            on_error = lambda ws, err: self.__on_error(ws, err),
            on_close = lambda ws: self.__on_close(ws),
            on_open = lambda ws: self.__on_open(ws)
        )

        self._ws_thread = threading.Thread(target=self._ws.run_forever, kwargs={'origin': ClientWebSocket.origin_url})
        self._ws_thread.daemon = True
        self._ws_thread.start()

    def ws_send(self, message_tag, payload, trace_payload=None):
        msg = message_tag + ','
        if type(payload) in (dict, list):
            msg += json.dumps(payload)
        elif type(payload) is bytes:
            msg = msg.encode() + payload
        else:
            msg += payload

        if self._enable_trace and (type(msg) is not bytes or trace_payload is not None):
            trace_msg = trace_payload if trace_payload is not None else msg
            if len(trace_msg) > self._trace_truncate:
                print('Send: {}'.format(trace_msg[0:self._trace_truncate] + '...'))
            else:
                print('Send: {}'.format(trace_msg))
        self._ws.send(msg)

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

            if 'json' in msg_data and type(msg_data['json']) is list and len(msg_data['json']) >= 1:
                if not self.payload_action(msg_data['json']):
                    print_unknown_msg(message_tag, msg_data)
            else:
                print_unknown_msg(message_tag, msg_data)
                self._received_msgs[message_tag] = msg_data
        except Exception as e:
            eprint_report('Invalid msg: {},({}){}'.format(message_tag, 'json' if 'json' in msg_data else 'data', msg_data['json'] if 'json' in msg_data else msg_data['data']), add_traceback=True)

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

    def presence_loop(self):
        time.sleep(15)
        while self._state == State.OPEN:
            self._ws.send('?,,')
            time.sleep(30)

    def run_presence_loop(self):
        self._presence_thread = threading.Thread(target=self.presence_loop)
        self._presence_thread.daemon = True
        self._presence_thread.start()
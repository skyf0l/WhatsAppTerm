import websocket

import re
import requests

import time
import threading

import json
import base64, os

from enum import Enum, unique

def wait_until(somepredicate, timeout, period=0.05, *args, **kwargs):
    mustend = time.time() + timeout
    while time.time() < mustend:
        if somepredicate(*args, **kwargs): return True
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

@unique
class State(Enum):
    OPENING = 0
    OPEN = 1
    CLOSED = 2

class Client(object):

    whatsapp_wss_url = 'wss://web.whatsapp.com/ws'
    origin_url = 'https://web.whatsapp.com'

    def __init__(self, debug=False, enableTrace=False, **kwargs):

        websocket.enableTrace(enableTrace)

        self._debug = debug
        self._state = State.OPENING

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

        if wait_until(lambda self: self._state == State.OPEN, 10, self=self) == False:
            raise Exception('Websocket timed out')

        self._client_id = base64.b64encode(os.urandom(16))
        self._whatsappweb_version = get_whatsappweb_version()

        loggin_json = ['admin', 'init', self._whatsappweb_version, self._browser_desc, str(self._client_id), True]
        self.__send('connection_query', loggin_json)

        if wait_until(lambda self: 'connection_query' in self._received_msgs, 3, self=self) == False:
            raise Exception('Receive message timed out')


    def __send(self, messageTag, payload):
        msg = messageTag + ','
        if type(payload) in (dict, list):
            msg += json.dumps(payload)
        else:
            msg += payload
        if self._debug:
            print('Send: {}'.format(msg))
        self._ws.send(msg)

    def __on_message(self, ws, msg):
        if self._debug:
            print('Recv: {}'.format(msg))
        messageTag = msg.split(',')[0]
        payload = msg[len(messageTag) + 1:]
        self._received_msgs[messageTag] = payload

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

import websocket
import threading

from enum import Enum, unique

@unique
class State(Enum):
    OPENING = 0
    OPEN = 1
    CLOSED = 2

class Client(object):

    whatsapp_wss_url = 'wss://web.whatsapp.com/ws'
    origin_url = 'https://web.whatsapp.com'

    def __init__(self, enableTrace=False):

        websocket.enableTrace(enableTrace)

        self.state = State.OPENING
        self.ws = websocket.WebSocketApp(Client.whatsapp_wss_url,
            on_message = lambda ws, msg: self.__on_message(ws, msg),
            on_error = lambda ws, err: self.__on_error(ws, err),
            on_close = lambda ws: self.__on_close(ws),
            on_open = lambda ws: self.__on_open(ws)
        )

        self.ws_thread = threading.Thread(target=self.ws.run_forever, kwargs={'origin': Client.origin_url})
        self.ws_thread.daemon = True
        self.ws_thread.start()

    def __on_message(self, ws, msg):
        print(msg)

    def __on_error(self, ws, err):
        print(err)

    def __on_close(self, ws):
        self.state = State.CLOSED
        print("### Disconnected from chat. ###")

    def __on_open(self, ws):
        self.state = State.OPEN
        print('open')
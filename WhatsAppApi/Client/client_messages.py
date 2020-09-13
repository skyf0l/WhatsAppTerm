from ..defines import *
from ..utilities import *

class ClientMessages():

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
                'participant' : message['participant'].replace('s.whatsapp.net', 'c.us') if 'participant' in message else jid,
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

            if len(self._chats_messages[jid]) == 0:
                self._chats_messages[jid].append(msg)
            elif msg['at'] < self._chats_messages[jid][0]['at']:
                self._chats_messages[jid].insert(0, msg)
            else:
                self._chats_messages[jid].append(msg)
        except Exception as e:
            eprint_report('Invalid chat message: {}'.format(message), add_traceback=True)

    def add_messages(self, messages):
        for message in messages[::-1]:
            self.add_message(message)
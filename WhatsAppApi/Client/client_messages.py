import binascii

from Crypto import Random

from ..BinaryMessages.binary_writer import write_binary

from ..defines import *
from ..utilities import *

class ClientMessages():

    '''
    Conversation
        'conversation': 'text_message'

    SenderKeyDistributionMessage
    ImageMessage
        'imageMessage': {
            'url': 'https://mmg.whatsapp.net/.../file.enc',
            'mimetype': 'image/jpeg',
            'caption': 'text_message',
            'fileSha256': 'b64_hash',
            'fileLength': 'size',
            'height': height,
            'width': width,
            'mediaKey': 'b64_key',
            'fileEncSha256': 'b64_hash',
            'directPath': '/.../file.enc?oh=...&oe=...',
            'mediaKeyTimestamp': 'timestamp',
            'jpegThumbnail': 'b64_thumbnail'
        }

    ContactMessage
        'contactMessage': {
            'displayName': 'FirstName LastName',
            'vcard': 'BEGIN:VCARD\nVERSION:3.0\nN:LastName;FirstName;;;\nFN:FirstName LastName\nitem1.TEL;waid=336...:+33 6 ...\nitem1.X-ABLabel:Mobile\nEND:VCARD'
        }

    LocationMessage
        'locationMessage': {
            'degreesLatitude': float_latitude,
            'degreesLongitude': float_longitude,
            'jpegThumbnail': 'b64_map_thumbnail'
        }

    ExtendedTextMessage
        'extendedTextMessage': {
            'text':'msg',
            'previewType':'NONE',
            'contextInfo':{
                'stanzaId':'msg_id',
                'participant':'sender_jid@s.whatsapp.net',
                'quotedMessage': {
                    'conversation'/'contactMessage'/'videoMessage'/...: content
                }
            }
        }

    DocumentMessage
        'documentMessage': {
            'mimetype': 'application/pdf'/'application/*'/'image/jpeg',
            'title': '~filename',
            'fileLength': 'size',
            'pageCount': 0 (or nb pdf pages),
            'fileName': 'filename',
            +/- 'jpegThumbnail': 'b64_thumbnail'
        }
        then 'documentMessage': {
            'mimetype': 'application/pdf'/'application/*'/'image/jpeg',
            'title': '~filename',
            'fileSha256': 'hash',
            'fileLength': 'size',
            'pageCount': 0 (or nb pdf pages),
            'fileName': 'filename',
            'fileEncSha256': 'hash',
            +/- 'jpegThumbnail': 'b64_thumbnail'
        }

    AudioMessage
        music 'audioMessage': {
            'fileLength': 'size',
            'seconds': length(in s),
            'ptt': False
        }
        then 'audioMessage': {
            'fileSha256': 'b64_hash',
            'fileLength': 'size',
            'seconds': length(in s),
            'ptt': False,
            'fileEncSha256': 'b64_hash'
        }
        audio message 'audioMessage': {
            'fileSha256': 'b64_hash',
            'fileLength': 'size',
            'seconds': length(in s),
            'ptt': True,
            'fileEncSha256': 'b64_hash'
        }
        then 'audioMessage': {
            'fileSha256': 'b64_hash (same)',
            'fileLength': 'size',
            'seconds': length(in s),
            'ptt': True,
            'fileEncSha256': 'b64_hash (same)'
        }

    VideoMessage
        video: 'videoMessage': {
            'url': 'https://mmg.whatsapp.net/.../file.enc',
            'mimetype': 'video/mp4',
            'fileSha256': 'b64_hash',
            'fileLength': 'size',
            'seconds': length(in s),
            'mediaKey': 'b64_hash',
            'caption': 'text_message',
            'height': height,
            'width': width,
            'fileEncSha256': 'b64_hash',
            'directPath': '/.../file.enc?oh=...&oe=...',
            'mediaKeyTimestamp': 'timestamp',
            'jpegThumbnail': 'b64_thumbnail'
        }
        GIF: 'videoMessage': {
            +/- 'fileSha256': 'b64_hash',
            'fileLength': 'size',
            'seconds': length(in s),
            'gifPlayback': True,
            +/- 'fileEncSha256': 'b64_hash',
            'jpegThumbnail': 'b64_thumbnail',
            'gifAttribution': 'NONE'
        }
        quoted: 'videoMessage': {
            'fileSha256': 'b64_hash',
            'fileLength': 'size',
            'seconds': length(in s),
            'fileEncSha256': 'b64_hash',
            'jpegThumbnail': 'b64_thumbnail'
        }

    Call
    Chat
    ProtocolMessage
    ContactsArrayMessage
    HighlyStructuredMessage
    FastRatchetKeySenderKeyDistributionMessage
    SendPaymentMessage
    LiveLocationMessage
        'liveLocationMessage': {
            'degreesLatitude': float_latitude,
            'degreesLongitude': float_longitude,
            'sequenceNumber': '0'
        }
        then 'liveLocationMessage': {
            'degreesLatitude': float_latitude,
            'degreesLongitude': float_longitude,
            'sequenceNumber': 'id',
            'jpegThumbnail': 'b64_map_thumbnail'
        }

    RequestPaymentMessage
    DeclinePaymentRequestMessage
    CancelPaymentRequestMessage
    TemplateMessage
    StickerMessage
        if send 'stickerMessage': {
            'fileSha256': 'b64_hash',
            'mimetype': 'image/webp',
            'fileLength': 'size'
        }
        then 'stickerMessage': {
            'fileSha256': 'b64_hash',
            'fileEncSha256': 'b64_hash',
            'mimetype': 'image/webp',
            'fileLength': 'size'
        }
        if load 'stickerMessage': {
            'url': 'https://mmg.whatsapp.net/.../file.enc',
            'fileSha256': 'b64_hash',
            'fileEncSha256': 'b64_hash',
            'mediaKey': 'b64_hash',
            'mimetype': 'image/webp',
            'directPath': '/.../file.enc?oh=...&oe=...',
            'fileLength': 'size',
            'mediaKeyTimestamp': 'timestamp'
        }
    '''

    def parse_message_content(self, message_content):
        message = {
            'type': MessageType.get(list(message_content.keys())[0]),
            'text': None,
            'content': None
        }

        message_data = message_content[MessageType.to_string(message['type'])]

        if message['type'] == MessageType.Conversation:
            message['text'] = message_data

        elif message['type'] == MessageType.ImageMessage:
            if 'caption' in message_data:
                message['text'] = message_data['caption']

        elif message['type'] == MessageType.LocationMessage:
            message['text'] = 'Map location: {}, {}'.format(message_data['degreesLatitude'], message_data['degreesLongitude'])

        elif message['type'] == MessageType.ContactMessage:
            message['content'] = {
                'display_name': message_data['displayName'],
                'vcard': message_data['vcard']
            }

        elif message['type'] == MessageType.ExtendedTextMessage:
            message['text'] = message_data['text']

        elif message['type'] == MessageType.DocumentMessage:
            message['text'] = 'Document: {}'.format(message_data['title'])

        elif message['type'] == MessageType.AudioMessage:
            pass

        elif message['type'] == MessageType.VideoMessage:
            if 'caption' in message_data:
                message['text'] = message_data['caption']

        elif message['type'] == MessageType.LiveLocationMessage:
            message['text'] = 'Map live location: {}, {}'.format(message_data['degreesLatitude'], message_data['degreesLongitude'])

        elif message['type'] == MessageType.StickerMessage:
            pass

        else:
            wprint_report('Unknown message content: {}'.format(message_content))

        return message

    def parse_quoted_message_content(self, quoted_message_content):
        quoted_message = self.parse_message_content(quoted_message_content['quotedMessage'])
        quoted_message['id'] = quoted_message_content['stanzaId']
        quoted_message['participant'] = quoted_message_content['participant']
        return quoted_message

    def add_message(self, message):
        try:
            jid = message['key']['remoteJid'].replace('s.whatsapp.net', 'c.us')
            if jid not in self._chats_messages:
                self._chats_messages[jid] = []

            msg = {
                'id': message['key']['id'],
                'from_me': message['key']['fromMe'],
                'at': int(message['messageTimestamp']),
                'message': None,
                'quoted_message': None,
                'participant' : message['participant'].replace('s.whatsapp.net', 'c.us') if 'participant' in message else jid,
                'message_stub' : MessageStubType.get(message['messageStubType']) if 'messageStubType' in message else None,
                'message_stub_parameters' : message['messageStubParameters'] if 'messageStubParameters' in message else None,
                'status': MessageStatus.Error if 'status' not in message else MessageStatus.get(message['status'])
            }
            if 'message' in message:
                msg['message'] = self.parse_message_content(message['message'])
                if 'contextInfo' in message['message'][MessageType.to_string(msg['message']['type'])]:
                    msg['quoted_message'] = self.parse_quoted_message_content(message['message'][MessageType.to_string(msg['message']['type'])]['contextInfo'])
                

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

    def send_text_message(self, number, text):
        messageId = '3EB0' + str(binascii.hexlify(Random.get_random_bytes(8)).upper(), 'utf8')

        number = number.split('@')[0]
        messageParams = {'key': {'fromMe': True, 'remoteJid': number + '@s.whatsapp.net', 'id': messageId},'messageTimestamp': get_timestamp(), 'status': 1, 'message': {'conversation': text}}
        msgData = ['action', {'type': 'relay', 'epoch': str(self._nb_msg_sent)},[['message', None, WebMessage.encode(messageParams)]]]
        encryptedMessage = self.encrypt_msg(write_binary(msgData))
        payload = b'\x10\x80' + encryptedMessage

        self.ws_send(messageId, payload, trace_payload=msgData)
        self._nb_msg_sent += 1
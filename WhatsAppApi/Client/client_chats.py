from ..defines import *
from ..utilities import *

class ClientChats():

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
        
    def add_chats(self, chats):
        for chat in chats:
            if len(chat) == 3 and chat[0] == 'chat' and chat[2] == None:
                self.add_chat(chat[1])
            else:
                eprint_report('Unknown chat format: {}'.format(chat))

        # order chats by t
        self._chats.sort(key=lambda chat: chat['t'], reverse=True)
        self._chats_loaded = True
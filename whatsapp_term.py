#!/usr/bin/python3

from WhatsAppApi import Client, Color, MessageType, MessageStubType

import os, sys
import time
from datetime import datetime

import urwid

class Chat(object):

    def __init__(self):

        self._client = Client(enable_trace=True, session_path='current.session')
        self._chat_id = -1

        while self._client.must_scan_qrcode():
            qrcodes = self._client.get_qrcode()
            print(qrcodes['small'])
            self._client.qrcode_ready_to_scan()

    def get_author_name(contact):
        if contact is None:
            return '???'
        elif contact['short'] is not None:
            return contact['short']
        elif contact['name'] is not None:
            return contact['name']
        elif contact['notify'] is not None:
            return contact['notify']
        return contact['jid'].split('@')[0]

    def display_chat(self):
        chats = self._client.get_chats()
        chat = chats[self._chat_id]
        messages = self._client.get_messages(chat['jid'])
        name = chat['name'] if chat['name'] is not None else chat['jid'].split('@')[0]

        print('-> ' + name)
        for message in messages:
            if chat['type'] == 'user':
                author = (Color.Green + 'You' + Color.Reset) if message['from_me'] else (Color.Blue + name + Color.Reset)
            else:
                author_contact = self._client.get_contact(message['participant'])
                author = (Color.Green + 'You' + Color.Reset) if message['from_me'] else (Color.Blue + Chat.get_author_name(author_contact) + Color.Reset)
            dt_object = datetime.fromtimestamp(message['at'])
            date, hour = str(dt_object).split(' ')
            if message['message'] is not None:
                print('{} <{}> {}'.format(hour, author,
                    message['message']['text'] if message['message'] is not None and message['message']['text'] is not None else MessageType.to_string(message['message']['type'])))
            if message['message_stub'] is not None:
                print('{} <{}> {} - {}'.format(hour, author, MessageStubType.to_string(message['message_stub']), message['message_stub_parameters']))


    def display_chats(self):
        chats = self._client.get_chats()
        for chat_id in range(len(chats)):
            chat = chats[chat_id]
            name = chat['name'] if chat['name'] is not None else chat['jid']
            print('{}/ {} - ({})'.format(chat_id, name, chat['not_read_count']))
            
    def cmd_input(self, cmd):
        if cmd == '/help':
            print('/chats       see all chats')
            print('/chat id     open chat number `id`')
            return True
        elif cmd == '/chats':
            self.display_chats()
            return True
        elif cmd.split(' ')[0] == '/chat' and len(cmd.split(' ')) == 2:
            try:
                chat_id = int(cmd.split(' ')[1])
            except Exception:
                return False
            self._chat_id = chat_id
            self.display_chat()
            return True
        return False

    def run(self):
        while True:
            try:
                cmd = input('> ')
            except EOFError:
                break
            if self.cmd_input(cmd) == False:
                print('invalid command, type \'/help\' for more information')

def main():
    chat = Chat()
    chat.run()

if __name__ == "__main__":
    main()
#!/usr/bin/python3

from WhatsAppApi import Client, Color, MessageType

import time
from datetime import datetime

client = Client(debug=False, enable_trace=True, restore_sessions=True)

while client.must_scan_qrcode():
    qrcodes = client.get_qrcode()
    print(qrcodes['small'])
    client.qrcode_ready_to_scan()

chats = client.get_chats()
for chat in chats:
    print((chat['name'] + ' ' + chat['jid'] if chat['name'] is not None else chat['jid']) + (' ({})'.format(chat['not_read_count']) if chat['not_read_count'] > 0 else ''))

time.sleep(4)

def get_author_name(contact):
    if contact['short'] is not None:
        return contact['short']
    elif contact['name'] is not None:
        return contact['name']
    elif contact['notify'] is not None:
        return contact['notify']
    return contact['jid'].split('@')[0]

for chat_id in range(2):
    chat = chats[chat_id]
    messages = client.get_messages(chat['jid'])
    name = chat['name'] if chat['name'] is not None else chat['jid'].split('@')[0]

    print('-> ' + name)
    for message in messages:
        if chat['type'] == 'user':
            author = (Color.Green + 'You' + Color.Reset) if message['from_me'] else (Color.Blue + name + Color.Reset)
        else:
            author_contact = client.get_contact(message['participant'])
            author = (Color.Green + 'You' + Color.Reset) if message['from_me'] else (Color.Blue + get_author_name(author_contact) + Color.Reset)
        dt_object = datetime.fromtimestamp(message['at'])
        date, hour = str(dt_object).split(' ')
        print('{} <{}> {}'.format(hour, author, message['message']['text'] if message['message']['text'] is not None else MessageType.to_string(message['message']['type'])))

while True:
    time.sleep(0.25)

# client.logout()
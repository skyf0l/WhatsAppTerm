#!/usr/bin/python3

from WhatsAppApi import Client, Color

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

time.sleep(2)

chat = chats[0]
messages = client.get_messages(chat['jid'])
name = chat['name'] if chat['name'] is not None else chat['jid'].split('@')[0]

print(name)
for message in messages:
	author = (Color.Green + 'You' + Color.Reset) if message['from_me'] else (Color.Blue + name + Color.Reset)
	dt_object = datetime.fromtimestamp(message['at'])
	date, hour = str(dt_object).split(' ')
	print('{} <{}> {}'.format(hour, author, message['message']['text']))

while True:
    time.sleep(0.25)

# client.logout()
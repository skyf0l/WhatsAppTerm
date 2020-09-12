#!/usr/bin/python3

from WhatsAppApi import Client

import time

client = Client(debug=False, enable_trace=True, restore_sessions=True)

while client.must_scan_qrcode():
    qrcodes = client.get_qrcode()
    print(qrcodes['small'])
    client.qrcode_ready_to_scan()

chats = client.get_chats()
for chat in chats:
	print(chat['name'] if chat['name'] is not None else chat['jid'])

while True:
    time.sleep(0.25)

# client.logout()
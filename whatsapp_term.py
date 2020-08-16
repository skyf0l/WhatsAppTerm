#!/usr/bin/python3

from WhatsAppApi import Client

import time

client = Client(debug=True)

print('wa start')

qrcodes = client.get_qrcode()
print(qrcodes['small'])

while True:
    time.sleep(0.25)
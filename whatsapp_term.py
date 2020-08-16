#!/usr/bin/python3

from WhatsAppApi import Client

import time

client = Client(debug=True)

while True:
    qrcodes = client.get_qrcode()
    print(qrcodes['small'])
    if client.qrcode_ready_to_scan():
        break


while True:
    time.sleep(0.25)
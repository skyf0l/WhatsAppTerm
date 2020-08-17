#!/usr/bin/python3

from WhatsAppApi import Client

import time

client = Client(debug=True, enable_trace=True, restore_sessions=False)

while client.must_scan_qrcode():
    qrcodes = client.get_qrcode()
    print(qrcodes['small'])
    client.qrcode_ready_to_scan()

client.logout()

while True:
    time.sleep(0.25)
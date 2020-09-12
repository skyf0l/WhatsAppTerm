import time

import traceback

import re
import requests

def wait_until(somepredicate, timeout, period=0.05, *args, **kwargs):
    mustend = time.time() + timeout
    while time.time() < mustend:
        if somepredicate(*args, **kwargs):
            return True
        time.sleep(period)
    return False

def eprint(msg):
    print(msg, file=sys.stderr)

def eprint_report(msg, add_traceback=False):
    RED_COLOR = '\033[91m'
    END_COLOR = '\033[0m'
    report = msg + '\n'
    if add_traceback == True:
        report += traceback.format_exc()
    report += 'Please, open an issue to fix it (hide private data)'
    eprint(RED_COLOR + report + END_COLOR)

def get_whatsappweb_version():
    url = 'https://web.whatsapp.com/'
    headers = {'User-Agent':'Mozilla/75 Gecko/20100101 Firefox/76'}

    result = requests.get(url, headers=headers)
    res = re.search(r'l=\"([0-9]+)\.([0-9]+)\.([0-9]+)\"', result.text)
    if res is None:
        raise ValueError('Can\'t find WhatsAppWeb version')
    return [int(res.group(1)), int(res.group(2)), int(res.group(3))]

def get_timestamp():
    return int(time.time());
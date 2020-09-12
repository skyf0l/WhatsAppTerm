import time

import sys
import traceback

import re
import requests

def wait_until(somepredicate, timeout, period=0.05, *args, **kwargs):
    if somepredicate(*args, **kwargs):
        return True
    mustend = time.time() + timeout
    while time.time() < mustend:
        if somepredicate(*args, **kwargs):
            return True
        time.sleep(period)
    return False

def eprint(msg):
    print(msg, file=sys.stderr)

def print_report(msg, color=None, add_traceback=False):
    START_COLOR = color if color is not None else ''
    END_COLOR = '\033[0m'
    report = msg + '\n'
    if add_traceback == True:
        report += traceback.format_exc()
    report += 'Please, to fix it, open an issue with this message (hide private data) and briefly explain how it happened'
    eprint(START_COLOR + report + END_COLOR)

def eprint_report(msg, add_traceback=False):
    RED_COLOR = '\033[91m'
    print_report(msg, color=RED_COLOR, add_traceback=add_traceback)

def wprint_report(msg, add_traceback=False):
    ORANGE_COLOR = '\033[93m'
    print_report(msg, color=ORANGE_COLOR, add_traceback=add_traceback)

def print_unknown_msg(message_tag, msg_data):
    ORANGE_COLOR = '\033[93m'
    END_COLOR = '\033[0m'
    msg = '{},({}){}'.format(message_tag, str('json' if 'json' in msg_data else 'data'), str(msg_data['json'] if 'json' in msg_data else msg_data['data']))
    report = 'Unknown msg: {}\nPlease, to fix it, open an issue with this message (hide private data) and briefly explain how it happened'.format(msg)
    eprint(ORANGE_COLOR + report + END_COLOR)

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
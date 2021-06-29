import time

import sys
import traceback

import re
import requests

class Color:
    Black = '\u001b[30m'
    Red = '\u001b[31m'
    Green = '\u001b[32m'
    Yellow = '\u001b[33m'
    Blue = '\u001b[34m'
    Magenta = '\u001b[35m'
    Cyan = '\u001b[36m'
    White = '\u001b[37m'
    BrightBlack = '\u001b[30;1m'
    BrightRed = '\u001b[31;1m'
    BrightGreen = '\u001b[32;1m'
    BrightYellow = '\u001b[33;1m'
    BrightBlue = '\u001b[34;1m'
    BrightMagenta = '\u001b[35;1m'
    BrightCyan = '\u001b[36;1m'
    BrightWhite = '\u001b[37;1m'
    Reset = '\u001b[0m'

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
    report = msg + '\n'
    if add_traceback == True:
        report += traceback.format_exc()
    report += 'Please, to fix it, open an issue with this message (hide private data) and briefly explain how it happened'
    eprint((color if color is not None else '') + report + Color.Reset)

def eprint_report(msg, add_traceback=False):
    print_report(msg, color=Color.Red, add_traceback=add_traceback)

def wprint_report(msg, add_traceback=False):
    print_report(msg, color=Color.Yellow, add_traceback=add_traceback)

def print_unknown_msg(message_tag, msg_data):
    msg = '{},({}){}'.format(message_tag, str('json' if 'json' in msg_data else 'data'), str(msg_data['json'] if 'json' in msg_data else msg_data['data']))
    report = 'Unknown msg: {}\nPlease, to fix it, open an issue with this message (hide private data) and briefly explain how it happened'.format(msg)
    eprint(Color.Yellow + report + Color.Reset)

def get_whatsappweb_version():
    url = 'https://web.whatsapp.com/'
    headers = {'User-Agent':'Mozilla/75 Gecko/20100101 Firefox/76'}

    result = requests.get(url, headers=headers)
    res = re.search(r'\w=\"([0-9]+)\.([0-9]+)\.([0-9]+)\"', result.text)
    if res is None:
        raise ValueError('Can\'t find WhatsAppWeb version')
    return [int(res.group(1)), int(res.group(2)), int(res.group(3))]

def get_timestamp():
    return int(time.time());
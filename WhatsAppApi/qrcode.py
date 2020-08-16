import base64
import pyqrcode

def split_by_line(string, line):
    splited = []
    lines = string.splitlines()
    for k in range(0, len(lines), line):
        splited.append((lines[0 + k:line + k]))
    return splited

def render_qrcode(bin_qrcode):
    big_qrcode = bin_qrcode.replace('0', '██').replace('1', '  ')

    small_qrcode = ''
    lines = split_by_line(bin_qrcode, 2)
    for line in lines:
        for char_id in range(len(line[0])):
            if len(line) == 2:
                if line[0][char_id] == '0' and line[1][char_id] == '0':
                    small_qrcode += '█'
                if line[0][char_id] == '0' and line[1][char_id] == '1':
                    small_qrcode += '▀'
                if line[0][char_id] == '1' and line[1][char_id] == '0':
                    small_qrcode += '▄'
                if line[0][char_id] == '1' and line[1][char_id] == '1':
                    small_qrcode += ' '
            else:
                if line[0][char_id] == '0':
                    small_qrcode += '▀'
                if line[0][char_id] == '1':
                    small_qrcode += ' '
        small_qrcode += '\n'

    big_qrcode = big_qrcode[:-1]
    small_qrcode = small_qrcode[:-1]
    return {'big': big_qrcode, 'small': small_qrcode}

def gen_qrcode(ref, publicKey, clientId):

    qrstring = '{},{},{}'.format(
        ref,
        str(base64.b64encode(publicKey.serialize()), 'utf8'),
        str(clientId), 'utf8')

    qrcode = pyqrcode.create(qrstring)
    bin_qrcode = qrcode.text(quiet_zone=1)
    return bin_qrcode

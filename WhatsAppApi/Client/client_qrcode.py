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

class ClientQRCode():

    def regen_qrcode(self):
        self._qrcode['id'] += 1

        new_qrcode_query_name = '{}.{}'.format('new_qrcode_query', '--{}'.format(self._qrcode['id']))
        self._expected_message_tags.append(new_qrcode_query_name)
        new_qrcode_query_json = ['admin', 'Conn', 'reref']
        self.ws_send(new_qrcode_query_name, new_qrcode_query_json)
        new_qrcode_result = self.wait_query_pop_json(new_qrcode_query_name)

        if new_qrcode_result['status'] != 200:
            raise ConnectionRefusedError('Websocket connection refused')
        self._qrcode['ref'] = new_qrcode_result['ref']
        self._qrcode['timeout'] = time.time() + self._qrcode['ttl']

        bin_qrcode = gen_qrcode(self._qrcode['ref'], self._publicKey, self._clientId)
        self._qrcode['qrcode'] = render_qrcode(bin_qrcode)

        if self._debug:
            print('QRCode regenerated')

    def qrcode_ready_to_scan(self):
        if self.load_s1234_queries() == False:
            self.regen_qrcode()
            return False

        if self._debug:
            print('QRCode scanned')

        self.generate_keys()

        if self._session_path != None:
            self.save_session()
        self._qrcode['must_scan'] = False

        self.post_login()
        return True

    def must_scan_qrcode(self):
        return self._qrcode['must_scan']

    def get_qrcode(self):
        return self._qrcode['qrcode']
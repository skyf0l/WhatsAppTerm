from .defines import Tags, ByteTokens, WebMessage

"""
inspired by
    https://github.com/sigalor/whatsapp-web-reveng/blob/master/backend/whatsapp_binary_reader.py
"""

class BinaryReader(object):

    def __init__(self, binary_data):
        self._binary_data = binary_data
        self._byte_id = 0

    def check_can_read(self, length):
        if self._byte_id + length > len(self._binary_data):
            raise EOFError('end of stream reached')

    def read_byte(self):
        self.check_can_read(1)
        value = self._binary_data[self._byte_id]
        self._byte_id += 1
        return value

    def read_bytes(self, n):
        self.check_can_read(n)
        value = self._binary_data[self._byte_id:self._byte_id + n]
        self._byte_id += n
        return value

    def read_intN(self, n):
        self.check_can_read(n)
        value = 0
        for k in range(n):
            value += self._binary_data[self._byte_id + k] << (8 * (n - 1 - k))
        self._byte_id += n
        return value

    def read_int16(self):
        return self.read_intN(2)

    def read_int20(self):
        byte_1 = self.read_byte()
        byte_2 = self.read_byte()
        byte_3 = self.read_byte()
        value = ((byte_1 & 15) << 16) + (byte_2 << 8) + byte_3
        return value

    def read_int32(self):
        return self.read_intN(4)

    def read_int64(self):
        return self.read_intN(8)

    def read_packed8(self, tag):
        start_byte = self.read_byte()
        value = ''
        for i in range(start_byte & 127):
            curr_byte = self.read_byte()
            value += self.unpack_byte(tag, (curr_byte & 0xF0) >> 4) + self.unpack_byte(tag, curr_byte & 0x0F)
        if (start_byte >> 7) != 0:
            value = value[:len(value) - 1]
        return value

    def unpack_byte(self, tag, value):
        if tag == Tags.NIBBLE_8:
            return self.unpack_nibble(value)
        elif tag == Tags.HEX_8:
            return self.unpack_hex(value)

    def unpack_nibble(self, value):
        if value >= 0 and value <= 9:
            return chr(ord('0') + value)
        elif value == 10:
            return '-'
        elif value == 11:
            return '.'
        elif value == 15:
            return '\0'
        raise ValueError('invalid nibble to unpack: ' + value)

    def unpack_hex(self, value):
        if value < 0 or value > 15:
            raise ValueError('invalid hex to unpack: ' + str(value))
        if value < 10:
            return chr(ord('0') + value)
        else:
            return chr(ord('A') + value - 10)

    def read_list_size(self, tag):
        if tag == Tags.LIST_EMPTY:
            return 0
        elif tag == Tags.LIST_8:
            return self.read_byte()
        elif tag == Tags.LIST_16:
            return self.read_int16()
        raise ValueError('invalid tag for list size: {}'.format(tag))

    def is_list_tag(self, tag):
        return tag == Tags.LIST_EMPTY or tag == Tags.LIST_8 or tag == Tags.LIST_16

    def read_string(self, tag):
        if tag >= 3 and tag <= 235:
            token = self.get_token(tag)
            if token == 's.whatsapp.net':
                token = 'c.us'
            return token

        if tag == Tags.DICTIONARY_0 or tag == Tags.DICTIONARY_1 or tag == Tags.DICTIONARY_2 or tag == Tags.DICTIONARY_3:
            return self.get_token_double(tag - Tags.DICTIONARY_0, self.read_byte())
        elif tag == Tags.LIST_EMPTY:
            return None
        elif tag == Tags.BINARY_8:
            return self.read_string_from_chars(self.read_byte())
        elif tag == Tags.BINARY_20:
            return self.read_string_from_chars(self.read_int20())
        elif tag == Tags.BINARY_32:
            return self.read_string_from_chars(self.read_int32())
        elif tag == Tags.JID_PAIR:
            i = self.read_string(self.read_byte())
            j = self.read_string(self.read_byte())
            if i is None or j is None:
                raise ValueError('invalid jid pair: ' + str(i) + ', ' + str(j))
            return i + '@' + j
        elif tag == Tags.NIBBLE_8 or tag == Tags.HEX_8:
            return self.read_packed8(tag)
        else:
            raise ValueError('invalid string with tag ' + str(tag))

    def read_string_from_chars(self, length):
        self.check_can_read(length);
        string = self._binary_data[self._byte_id:self._byte_id + length];
        self._byte_id += length;
        return string;

    def get_token(self, index):
        if index < 3 or index >= len(ByteTokens):
            raise ValueError('invalid token index: {}'.format(index))
        return ByteTokens[index]

    def get_token_double(self, index1, index2):
        raise ValueError('No token double')

    def read_attributes(self, n):
        attrs = {}
        if n == 0:
            return None
        for i in range(n):
            index = self.read_string(self.read_byte())
            attrs[index] = self.read_string(self.read_byte())
        return attrs

    def read_node(self):
        list_size = self.read_list_size(self.read_byte())
        tag_desc = self.read_byte()
        desc = self.read_string(tag_desc)
        attrs = self.read_attributes((list_size - 1) >> 1)
        if list_size % 2 == 1:
            return [desc, attrs, None]

        tag = self.read_byte()
        if self.is_list_tag(tag):
            content = self.read_list(tag)
        elif tag == Tags.BINARY_8:
            content = self.read_bytes(self.read_byte())
        elif tag == Tags.BINARY_20:
            content = self.read_bytes(self.read_int20())
        elif tag == Tags.BINARY_32:
            content = self.read_bytes(self.read_int32())
        else:
            content = self.read_string(tag)
        return [desc, attrs, content]

    def read_list(self, tag):
        content = []
        for _ in range(self.read_list_size(tag)):
            content.append(self.read_node())
        return content

def read_msg_array(content):
    if not isinstance(content, list):
        return content
    msg = []
    for x in content:
        if isinstance(x, list) and x[0] == 'message':
            msg.append(WebMessage.decode(x[2]))
        else:
            msg.append(x)
    return msg

def read_binary(binary_data, withMessages=False):
    msg = BinaryReader(binary_data).read_node()
    if withMessages and msg is not None and isinstance(msg, list) and msg[1] is not None:
        msg[2] = read_msg_array(msg[2])
    return msg
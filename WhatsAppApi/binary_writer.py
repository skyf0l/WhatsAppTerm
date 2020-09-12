from .defines import Tags, ByteTokens, WebMessage

"""
inspired by
    https://github.com/sigalor/whatsapp-web-reveng/blob/master/backend/utilities.py
    https://github.com/sigalor/whatsapp-web-reveng/blob/master/backend/whatsapp_binary_writer.py
"""

def getNumValidKeys(obj):
    return len(list(filter(lambda x: obj[x] is not None, list(obj.keys()))))

def encodeUTF8(s):
    if not isinstance(s, str):
        s = string.encode('utf-8')
    return s;

def ceil(n):
    res = int(n)
    return res if res == n or n < 0 else res + 1

class BinaryWriter(object):
    def __init__(self):
        self.data = []
    
    def get_data(self):
        return ''.join(map(chr, self.data)).encode()

    def push_byte(self, value):
        self.data.append(value & 0xFF)
    
    def push_intN(self, value, n, littleEndian):
        for i in range(n):
            currShift = i if littleEndian else n - 1 - i
            self.data.append((value >> (currShift*8)) & 0xFF)
    
    def push_int20(self, value):
        self.push_bytes([(value >> 16) & 0x0F, (value >> 8) & 0xFF, value & 0xFF])
    
    def push_int16(self, value):
        self.push_intN(value, 2)
    
    def push_int32(self, value):
        self.push_intN(value, 4)
    
    def push_int64(self, value):
        self.push_intN(value, 8)
    
    def push_bytes(self, bytes):
        self.data += bytes
    
    def push_string(self, str):
        self.data += map(ord, encodeUTF8(str))

    def write_byte_length(self, length):
        if length >= 4294967296:
            raise ValueError('string too large to encode (len = ' + str(length) + '): ' + str)
        
        if length >= (1 << 20):
            self.push_byte(Tags.BINARY_32)
            self.push_int32(length)
        elif length >= 256:
            self.push_byte(Tags.BINARY_20)
            self.push_int20(length)
        else:
            self.push_byte(Tags.BINARY_8)
            self.push_byte(length)

    def write_node(self, node):
        if node is None:
            return
        if not isinstance(node, list) or len(node) != 3:
            raise ValueError('invalid node: {}'.format(node))
        numAttributes = getNumValidKeys(node[1]) if bool(node[1]) else 0

        self.write_list_start(2 * numAttributes + 1 + (1 if bool(node[2]) else 0))
        self.write_string(node[0])
        self.write_attributes(node[1])
        self.write_children(node[2])
    
    def write_string(self, token, i=None):
        if not isinstance(token, str):
            raise ValueError('invalid string')

        if not bool(i) and token == 'c.us':
            self.write_token(ByteTokens.index('s.whatsapp.net'))
            return
        
        if token not in ByteTokens:
            jidSepIndex = token.index('@') if '@' in token else -1
            if jidSepIndex < 1:
                self.write_string_raw(token)
            else:
                self.write_jid(token[:jidSepIndex], token[jidSepIndex + 1:])
        else:
            tokenIndex = ByteTokens.index(token)
            if tokenIndex < Tags.SINGLE_BYTE_MAX:
                self.write_token(tokenIndex)
            else:
                singleByteOverflow = tokenIndex - Tags.SINGLE_BYTE_MAX
                dictionaryIndex = singleByteOverflow >> 8
                if dictionaryIndex < 0 or dictionaryIndex > 3:
                    raise ValueError('double byte dictionary token out of range: ' + token + ' ' + str(tokenIndex))
                self.write_token(Tags.DICTIONARY_0 + dictionaryIndex)
                self.write_token(singleByteOverflow % 256) 
    
    def write_string_raw(self, string):
        string = encodeUTF8(string)
        self.write_byte_length(len(string))
        self.push_string(string)
    
    def write_jid(self, jidLeft, jidRight):
        self.push_byte(Tags.JID_PAIR)
        if jidLeft is not None and len(jidLeft) > 0:
            self.write_string(jidLeft)
        else:
            self.write_token(Tags.LIST_EMPTY)
        self.write_string(jidRight)
    
    def write_token(self, token):
        if(token < 245):
            self.push_byte(token)
        elif token <= 500:
            raise ValueError('invalid token')
    
    def write_attributes(self, attrs):
        if attrs is None:
            return
        for key, value in attrs.items():
            if value is not None:
                self.write_string(key)
                self.write_string(value)
    
    def write_children(self, children):
        if children is None:
            return
        
        if isinstance(children, str):
            self.write_string(children, True)
        elif isinstance(children, bytes):
            self.write_byte_length(len(children))
            self.push_bytes(children)
        else:
            if not isinstance(children, list):
                raise ValueError('invalid children')
            self.write_list_start(len(children))
            for c in children:
                self.write_node(c)
    
    def write_list_start(self, listSize):
        if listSize == 0:
            self.push_byte(Tags.LIST_EMPTY)
        elif listSize < 256:
            self.push_bytes([ Tags.LIST_8, listSize ])
        else:
            self.push_bytes([ Tags.LIST_16, listSize ])
    
    def write_packed_bytes(self, string):
        try:
            self.write_packed_bytesImpl(string, Tags.NIBBLE_8)
        except e:
            self.write_packed_bytesImpl(string, Tags.HEX_8)
    
    def write_packed_bytesImpl(self, string, dataType):
        string = encodeUTF8(string)
        num_bytes = len(string)
        if num_bytes > Tags.PACKED_MAX:
            raise ValueError('too many bytes to nibble-encode: len = ' + str(num_bytes))
        
        self.push_byte(dataType)
        self.push_byte((128 if (num_bytes%2)>0 else 0) | ceil(num_bytes/2))

        for i in range(num_bytes // 2):
            self.push_byte(self.pack_byte_pair(dataType, string[2*i], str[2*i + 1]))
        if (num_bytes % 2) != 0:
            self.push_byte(self.pack_byte_pair(dataType, string[num_bytes - 1], '\x00'))
    
    def pack_byte_pair(self, pack_type, part1, part2):
        if pack_type == Tags.NIBBLE_8:
            return (self.pack_nibble(part1) << 4) | self.pack_nibble(part2)
        elif pack_type == Tags.HEX_8:
            return (self.pack_hex(part1) << 4) | self.pack_hex(part2)
        else:
            raise ValueError('invalid byte pack type: ' + str(pack_type))

    def pack_nibble(self, value):
        if value >= '0' and value <= '9':
            return int(value)
        elif value == '-':
            return 10
        elif value == '.':
            return 11
        elif value == '\x00':
            return 15
        raise ValueError('invalid byte to pack as nibble: ' + str(value))
    
    def pack_hex(self, value):
        if (value >= '0' and value <= '9') or (value >= 'A' and value <= 'F') or (value >= 'a' and value <= 'f'):
            return int(value, 16)
        elif value == '\x00':
            return 15
        raise ValueError('invalid byte to pack as hex: ' + str(value))

def write_binary(msg):
    stream = BinaryWriter()
    stream.write_node(msg)
    return stream.get_data()

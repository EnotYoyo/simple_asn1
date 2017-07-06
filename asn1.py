class ASN1(object):
    def __init__(self):
        self.obj_to_byte = {'list': 0x30, 'tuple': 0x31, 'bytes': 0x04, 'int': 0x02, 'str': 0x0c}
        self.byte_to_obj = {0x30: 'list', 0x31: 'tuple', 0x04: 'bytes', 0x02: 'int', 0x0c: 'str'}

    def _calc_len(self, b_array):
        l = len(b_array)
        if l < 0x80:
            return bytes([l])
        else:
            length = self.parse_obj_int(l)
            _l = len(length)
            return bytes([0x80 + _l]) + length

    def _get_len(self, b_array):
        if b_array[0] < 0x80:
            return b_array[0], b_array[1:]
        else:
            return self.parse_bytes_int(b_array[1:], b_array[0] - 0x80)

    def parse_bytes_list(self, b_array, length):
        if length == 0:
            return [], b_array
        results = []
        tail = bytes()
        if length != len(b_array):
            tail = b_array[length:]
            b_array = b_array[:length]
        while True:
            obj = self.byte_to_obj[b_array[0]]
            length, b_array = self._get_len(b_array[1:])
            obj, b_array = getattr(self, 'parse_bytes_' + obj)(b_array, length)
            results.append(obj)
            if len(b_array) == 0:
                return results, tail

    def parse_bytes_tuple(self, b_array, length):
        obj, b_array = self.parse_bytes_list(b_array, length)
        return tuple(obj), b_array

    def parse_bytes_bytes(self, b_array, length):
        return b_array[:length], b_array[length:]

    def parse_bytes_int(self, b_array, length):
        return int.from_bytes(b_array[:length], 'big'), b_array[length:]

    def parse_bytes_str(self, b_array, length):
        return b_array[:length].decode(), b_array[length:]

    def parse_obj_list(self, obj):
        result = bytes()
        for x in obj:
            result += self.encrypt(x)
        return result

    def parse_obj_tuple(self, obj):
        return self.parse_obj_list(obj)

    def parse_obj_bytes(self, obj):
        return obj

    def parse_obj_int(self, obj):
        return b'\0' + obj.to_bytes((obj.bit_length() + 7) // 8, 'big') or b'\0'

    def parse_obj_str(self, obj):
        return obj.encode()

    def encrypt(self, obj):
        name = obj.__class__.__name__
        tag = bytes([self.obj_to_byte[name]])
        data = getattr(self, 'parse_obj_' + name)(obj)
        length = self._calc_len(data)
        return tag + length + data

    def decrypt(self, byte_array):
        obj = self.byte_to_obj[byte_array[0]]
        length, byte_array = self._get_len(byte_array[1:])
        obj, byte_array = getattr(self, 'parse_bytes_' + obj)(byte_array, length)
        if len(byte_array) != 0:
            return obj, byte_array
        else:
            return obj, bytes()


def example():
    asn1 = ASN1()
    obj = [tuple([bytes([0x00, 0x01]), 'test', [100, 3], [], [0x00]]), [bytes([0x01, 0x32]), 1000]]
    asn_bytes = asn1.encrypt(obj)
    assert obj != asn1.decrypt(asn_bytes)

if __name__ == '__main__':
    example()

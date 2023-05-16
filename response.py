import query


class Response:
    def __init__(self, message):
        self.id = message[:2]
        self.flags = message[2:4]
        self.questions_count = message[4:6]  # QDCOUNT,
        self.answers_count = message[6:8]  # ANCOUNT,
        self.ns_count = message[8:10]  # NSCOUNT,
        self.additional_count = message[10:12]  # ARCOUNT
        byte_number = 12
        while message[byte_number] != 0:
            byte_number += 1
        byte_number += 1
        self.name = message[12: byte_number]
        self.mes_type = message[byte_number:byte_number + 2]
        self.mes_class = message[byte_number + 2:byte_number + 4]
        self.answers, byte_number = self._read_answers(message, byte_number + 4,
                                                       int.from_bytes(self.answers_count, 'big'))
        self.ns, byte_number = self._read_answers(message, byte_number, int.from_bytes(self.ns_count, 'big'))
        self.additional, byte_number = self._read_answers(message, byte_number,
                                                          int.from_bytes(self.additional_count, 'big'))

    def _read_name(self, byte_number, message: bytes):
        name = bytes()

        if byte_number <= len(message):
            while message[byte_number] != 0:
                if message[byte_number] == 192:
                    offset = message[byte_number + 1]
                    old_byte_number = offset
                    res = self._read_name(old_byte_number, message)
                    name += res[0]
                    byte_number += 1
                    break
                else:
                    name += message[byte_number].to_bytes(1, 'big')
                    byte_number += 1

            return name, byte_number + 1
        else:
            return None, byte_number

    def _read_answers(self, message, byte_number, amount):
        if amount == 0:
            return None, byte_number
        count = 0
        ans = []
        number = byte_number

        while count < amount:
            temp_ans = {}
            temp_ans['name'], number = self._read_name(number, message)
            temp_ans['type'] = message[number: number + 2]
            temp_ans['class'] = message[number + 2: number + 4]
            temp_ans['ttl'] = message[number + 4: number + 8]
            temp_ans['rdlength'] = message[number + 8: number + 10]
            offset_data = int.from_bytes(temp_ans['rdlength'], 'big')
            number = number + 10

            if temp_ans['type'] == b'\x00\x01':
                temp_ans['ip'] = message[number: number + offset_data]
                number += offset_data
            elif temp_ans['type'] == b'\x00\x02':
                temp_ans['name_server'] = self._read_name(number, message)[0]
                number += offset_data
            elif temp_ans['type'] == b'\x00\x06':
                temp_ans['mname'], number = self._read_name(number, message)
                temp_ans['rname'], number = self._read_name(number, message)
                temp_ans['serial'] = message[number: number + 4]
                temp_ans['refresh'] = message[number + 4: number + 8]
                temp_ans['retry'] = message[number + 8: number + 12]
                temp_ans['expire'] = message[number + 12: number + 16]
                temp_ans['minimum'] = message[number + 16: number + 20]
                number = number + 20
            elif temp_ans['type'] == b'\x00\x0f':
                temp_ans['preference'] = message[number: number + 2]
                temp_ans['exchange'], number = self._read_name(number + 2, message)
            ans.append(temp_ans)
            count += 1

        return ans, number

    @staticmethod
    def make_response(data: [], dns_query: query.Query):

        def _encode_ip(ip: str):
            encode_ip = bytes()
            ip_parts = ip.split('.')
            for part in ip_parts:
                part = int(part)
                encode_ip += part.to_bytes(1, 'big')

            return encode_ip

        def _encode_name(name: str, names: dict, byte_number: int):
            encode_name = bytes()
            if name[-1] == '.':
                name = name[:-1]
            count = len(name)
            while count > 0:
                if name in names.keys():
                    encode_name = encode_name + names[name]
                    count = 0
                    byte_number += 2
                else:
                    names[name] = b'\xc0' + byte_number.to_bytes(1, 'big')
                    first_dot = name.split('.')[0]
                    length = len(first_dot).to_bytes(1, 'big')
                    encode_name = encode_name + length + first_dot.encode('utf-8')
                    count = count - len(first_dot)
                    if count == 0:
                        encode_name += b'\x00'
                        byte_number += 1
                    count -= 1
                    name = name[len(first_dot) + 1:]
                    byte_number += len(first_dot) + 1

            return encode_name, names, byte_number

        flags1 = (dns_query.flags[0] | int.from_bytes(b'\x80', 'big'))  # установка флага Response
        flags1 = flags1 & int.from_bytes(b'\xfb', 'big')  # установка флага АА в 0
        flags2 = dns_query.flags[1] | int.from_bytes(b'\x80', 'big')  # установка флага RA

        if not data:
            pass

        resp = dns_query.id + flags1.to_bytes(1, 'big') + flags2.to_bytes(1, 'big') + dns_query.questions + \
               len(data).to_bytes(2, 'big') + dns_query.ns + dns_query.additional + dns_query.name + \
               dns_query.mes_type + dns_query.mes_class

        byte_number = 12
        try:
            res = _encode_name(data[0]['name'], {}, byte_number)
            dict_with_names = res[1]
            byte_number = res[2] + 4
        except IndexError:
            dict_with_names = {}

        answer_part = bytes()
        for save_answer in data:
            temp_ans = bytes()
            name, dict_with_names, byte_number = _encode_name(save_answer['name'], dict_with_names, byte_number)
            temp_ans += name
            temp_ans += dns_query.mes_type
            temp_ans += dns_query.mes_class
            temp_ans += save_answer['ttl'].to_bytes(4, 'big')
            temp_ans += save_answer['rdlength'].to_bytes(2, 'big')
            byte_number += 10
            if save_answer['type'] == 'A':
                temp_ans += _encode_ip(save_answer['ip'])
            elif save_answer['type'] == 'NS':
                name, dict_with_names, byte_number = _encode_name(save_answer['name_server'], dict_with_names,
                                                                  byte_number)
                temp_ans += name
            elif save_answer['type'] == 'MX':
                temp_ans += save_answer['preference'].to_bytes(2, 'big')
                name, dict_with_names, byte_number = _encode_name(save_answer['name_server'], dict_with_names,
                                                                  byte_number)
                temp_ans += name
            elif save_answer['type'] == 'SOA':
                mname, dict_with_names, byte_number = _encode_name(save_answer['mname'], dict_with_names,
                                                                   byte_number)
                temp_ans += mname
                rname, dict_with_names, byte_number = _encode_name(save_answer['rname'], dict_with_names,
                                                                   byte_number)
                temp_ans += rname
                temp_ans += save_answer['serial'].to_bytes(4, 'big')
                temp_ans += save_answer['refresh'].to_bytes(4, 'big')
                temp_ans += save_answer['retry'].to_bytes(4, 'big')
                temp_ans += save_answer['expire'].to_bytes(4, 'big')
                temp_ans += save_answer['minimum'].to_bytes(4, 'big')

            answer_part += temp_ans
        return resp + answer_part

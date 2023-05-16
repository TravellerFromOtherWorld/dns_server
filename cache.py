import query
import response
import json


class Cache:
    def __init__(self):
        self._file = "cache.json"

    def check_cache(self, dns_query: query.Query):
        dicts_to_return = []
        with open(self._file, 'r') as cache_file:
            try:
                cache_data = json.load(cache_file)
                key1 = self._decode_name(dns_query.name)[:-1]
                key2 = self._decode_type(dns_query.mes_type)
                try:
                    for save_data in cache_data[key1][key2]:
                        temp_dict = {'name': key1, 'type': key2}
                        for save_key, save_value in save_data.items():
                            temp_dict[save_key] = save_value
                        dicts_to_return.append(temp_dict)
                    return dicts_to_return
                except KeyError:
                    return None
            except json.decoder.JSONDecodeError:
                return None

    def save_cache(self, dns_response: response.Response):
        self.parse_and_save_answer(dns_response.answers)
        self.parse_and_save_answer(dns_response.ns)
        self.parse_and_save_answer(dns_response.additional)

    def parse_and_save_answer(self, data: []):
        if data is None:
            return

        for answer in data:
            dict_to_dump = {}
            key1 = self._decode_name(answer['name'])
            key2 = self._decode_type(answer['type'])
            dict_to_dump['class'] = 'IN'
            dict_to_dump['ttl'] = int.from_bytes(answer['ttl'], 'big')
            dict_to_dump['rdlength'] = int.from_bytes(answer['rdlength'], 'big')

            if key2 == 'A':
                dict_to_dump['ip'] = self.decode_ip(answer['ip'])
            elif key2 == 'NS':
                dict_to_dump['name_server'] = self._decode_name(answer['name_server'])
            elif key2 == 'SOA':
                dict_to_dump['mname'] = self._decode_name(answer['mname'])
                dict_to_dump['rname'] = self._decode_name(answer['rname'])
                dict_to_dump['serial'] = int.from_bytes(answer['serial'], 'big')
                dict_to_dump['refresh'] = int.from_bytes(answer['refresh'], 'big')
                dict_to_dump['retry'] = int.from_bytes(answer['retry'], 'big')
                dict_to_dump['expire'] = int.from_bytes(answer['expire'], 'big')
                dict_to_dump['minimum'] = int.from_bytes(answer['minimum'], 'big')
            elif key2 == 'MX':
                dict_to_dump['preference'] = int.from_bytes(answer['preference'], 'big')
                dict_to_dump['exchange'] = self._decode_name(answer['exchange'])

            with open(self._file, 'r+', encoding='utf-8') as cache_file:
                try:
                    cache_data = json.load(cache_file)
                    try:
                        if dict_to_dump not in cache_data[key1][key2]:
                            cache_data[key1][key2].append(dict_to_dump)
                    except KeyError:
                        if key1 not in cache_data.keys():
                            cache_data[key1] = {key2: [dict_to_dump]}
                        else:
                            cache_data[key1][key2] = []
                            cache_data[key1][key2].append(dict_to_dump)
                    finally:
                        cache_file.seek(0)
                        json.dump(cache_data, cache_file, indent=4)
                except json.decoder.JSONDecodeError:
                    cache_data = {key1: {key2: []}}
                    cache_data[key1][key2].append(dict_to_dump)
                    cache_file.seek(0)
                    json.dump(cache_data, cache_file, indent=4)

    def _decode_name(self, name):
        decode_name = ''
        count = 0

        while count != len(name):
            length = name[count]
            count += 1
            decode_name += name[count: count + length].decode('utf-8')
            decode_name += '.'
            count += length

        return decode_name[:-1]

    def _decode_type(self, mes_type):
        match mes_type:
            case b'\x00\x01':
                return 'A'
            case b'\x00\x02':
                return 'NS'
            case b'\x00\x06':
                return 'SOA'
            case b'\x00\x0f':
                return 'MX'

    @staticmethod
    def decode_ip(ip):
        decode_ip = ''

        for i in range(4):
            decode_ip += str(ip[i])
            decode_ip += '.'

        return decode_ip[:-1]

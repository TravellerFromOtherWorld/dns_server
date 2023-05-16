import json
import socket
import query
import response
import cache
from collections import deque


PORT = 53
HOST = '127.0.0.1'
BIG_BROTHER = '195.19.220.238'  # e1.ru (ns1.ngs.ru)
TEST_SITE = '195.19.220.24'  # e1.ru


def check_network():  # проверка на наличие сети
    try:
        s = socket.create_connection((TEST_SITE, 80), 2)
        s.close()
        return True
    except Exception:
        pass
    return False


def make_stack_query(name: bytes):
    res_queue = deque()
    res_queue.append(name)
    count = 0

    while count != len(name):
        length = name[count]
        count += 1
        count += length
        if length != 0:
            res_queue.append(name[count:])
    res_queue.pop()
    return res_queue


def ask_another_servers(message: query.Query, server: str):
    query_stack = make_stack_query(message.name)
    message.mes_type = b'\x00\x02'
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while len(query_stack) > 0:
        message.name = query_stack.pop()
        client.sendto(message.make_dns_query(), (server, PORT))
        recv, address = client.recvfrom(512)
        info = response.Response(recv)
        if info.ns:
            if info.additional:
                server = cache.Cache.decode_ip(info.additional[0]['ip'])
            else:
                message.name = info.ns[0]['name_server']
        elif info.answers:
            message.name = info.ns[0]['name_server']
        else:
            return None
    return server


def ask_someone_else(message: query.Query):
    print('Ask big brother')
    mes_type = message.mes_type
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(message.make_dns_query(), (BIG_BROTHER, PORT))
    recv, address = client.recvfrom(512)
    info = response.Response(recv)
    if info.answers is None and info.ns is None:
        print('Big brother doesn\'t know the answer')
        print('Ask another servers')
        with open("rootServers.json", 'r') as tld_file:
            try:
                root_servers = json.load(tld_file)
                server = root_servers[str(0)]
            except IndexError:
                return

        server = ask_another_servers(message, server)
        if server:
            message.mes_type = mes_type
            client.sendto(message.make_dns_query(), (server, PORT))
            recv, address = client.recvfrom(512)
            info = response.Response(recv)
        else:
            info = None

    return recv, info


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    print("Server is working")

    while True:
        message, address = s.recvfrom(512)

        dns_query = query.Query(message)
        if dns_query.flags[0] & (1 << 7):  # проверяем что нам пришло
            continue  # если не query -  игнорируем

        dns_cache = cache.Cache()
        cache_data = dns_cache.check_cache(dns_query)
        if cache_data:
            print('Find data in cache')
            resp = response.Response.make_response(cache_data, dns_query)
        else:
            if check_network():
                resp, info = ask_someone_else(dns_query)
                flags1 = resp[2]
                flags1 = flags1 & int.from_bytes(b'\xfb', 'big')
                resp = resp[:2] + flags1.to_bytes(1, 'big') + resp[3:]
                if info:
                    print('Answer has been found')
                    print('Save it in cache')
                    dns_cache.save_cache(info)
            else:
                resp = response.Response.make_response([], dns_query)
        print('Send results to client\n\n')
        s.sendto(resp, address)


if __name__ == "__main__":
    main()

class Query:
    def __init__(self, message):
        self.id = message[:2]
        self.flags = message[2:4]
        self.questions = message[4:6]  # QDCOUNT,
        self.answers = message[6:8]  # ANCOUNT,
        self.ns = message[8:10]  # NSCOUNT,
        self.additional = message[10:12]  # ARCOUNT
        byte_number = 12
        while message[byte_number] != 0:
            byte_number += 1
        byte_number += 1
        self.name = message[12: byte_number]
        self.mes_type = message[byte_number:byte_number + 2]
        self.mes_class = message[byte_number + 2:byte_number + 4]

    def make_dns_query(self):
        return self.id + self.flags + self.questions + self.answers + self.ns + self.additional + self.name + \
               self.mes_type + self.mes_class

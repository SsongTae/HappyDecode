import struct
import socket
from datetime import datetime
import traceback
import base64
from urllib import parse

HOST = ''
PORT = 80

class HappyCrypt:
    def decrypt(data: bytes):
        data += b'=' * (4 - len(data) % 4)
        decryptedData = bytearray(base64.b64decode(parse.unquote(data)))
        
        key = bytearray.fromhex("DD 33 99 CC")

        init = 0

        for i in range(0, len(decryptedData)):
            tmp = init ^ decryptedData[i] ^ key[i % 4]
            init = decryptedData[i]
            decryptedData[i] = tmp

        return decryptedData

    def encrypt(data):
        encryptedData = bytearray()
        key = bytearray.fromhex("DD 33 99 CC")

        init = 0

        for i in range(0, len(data)):
            tmp = init ^ data[i] ^ key[i % 4]
            init = tmp
            encryptedData.append(tmp)

        encryptedData = base64.b64encode(encryptedData)

        return encryptedData

class HappyPacket:
    def parsePacket(self, data):
        if len(data) < 0x3c:
            return False

        (self.random, self.unk_4, self.unk_8, self.ver) = struct.unpack("IIII", data[0:0x10])
        (self.userId, self.sig, self.type) = struct.unpack("QII", data[0x10:0x20])
        (self.unk_20, self.cmd, self.unk_28, self.unk_2c) = struct.unpack("IIII", data[0x20:0x30])
        (self.unk_30, self.length) = struct.unpack("QI", data[0x30:0x3c])

        data_pos_end = 0x3c + self.length
        self.data = data[0x3c:data_pos_end]
        self.remain_data = data[data_pos_end:]

        return True

    def printDetailPacket(self):
        print("================================================")
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("================================================")
        print(f"random : {hex(self.random)} / unk_4 : {hex(self.unk_4)} / unk_8 : {hex(self.unk_8)}")
        print(f"ver : {hex(self.ver)} / userId : {hex(self.userId)} / sig : {hex(self.sig)}")
        print(f"type : {hex(self.type)} / unk_20 : {hex(self.unk_20)} / cmd : {hex(self.cmd)}")
        print(f"unk_28 : {hex(self.unk_28)} / unk_2c : {hex(self.unk_2c)} / unk_30 : {hex(self.unk_30)} / length : {hex(self.length)}")
        print(f"data : {self.data}")
        print(f"remain_data : {self.remain_data}")
        print("================================================")

    def printPacket(self):
        print("================================================")
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("================================================")
        print(f"type : {hex(self.type)} / unk_20 : {hex(self.unk_20)} / cmd : {hex(self.cmd)}")
        print(f"unk_28 : {hex(self.unk_28)} / unk_2c : {hex(self.unk_2c)} / unk_30 : {hex(self.unk_30)} / length : {hex(self.length)}")
        print(f"data : {self.data}")
        print(f"remain_data : {self.remain_data}")
        print("================================================")

    def makePacket(self, data, cmd=None, unk_2c=None, unk_30=None):
        length = len(data)

        if cmd == None:
            cmd = self.cmd

        if unk_2c == None:
            unk_2c = self.unk_2c

        if unk_30 == None:
            unk_30 = self.unk_30

        makedPacket = struct.pack("IIII", self.random, self.unk_4, self.unk_8, self.ver)
        makedPacket += struct.pack("QII", self.userId, self.sig, self.type)
        makedPacket += struct.pack("IIII", self.unk_20, cmd, self.unk_28, unk_2c)
        makedPacket += struct.pack("QI", unk_30, length)
        makedPacket += data

        return makedPacket

    def getResponse(self):
        if self.type == 1 and self.unk_20 == 1:
            return self.makePacket(b"ok")
        elif self.type == 4 and self.unk_20 == 1:
            if self.unk_2c == 1:
                return self.makePacket(b"ok", unk_2c=0, unk_30=0)
            else:
                if self.unk_30 == 0x100000000:
                    return self.makePacket(b"ok", unk_2c=3)
                else:
                    return self.makePacket(b"ok", unk_30=(self.unk_30 + 1))
        elif self.type == 6 and self.unk_20 == 1:
            return self.makePacket(b"2777", cmd=1003)
        else:
            return self.makePacket(b"ok")

def generateResponse(data):
    headers = {
        "Server": "Apache/2.4.41 (Unix) OpenSSL/1.1.1d PHP/7.2.26 mod_perl/2.0.8-dev Perl/v5.16.3",
        "X-Powered-By": "PHP/7.2.26",
        "Content-Length": str(len(data)),
        "Keep-Alive": "timeout=5, max=96",
        "Connection": "Keep-Alive",
        "Content-Type": "text/html; charset=UTF-8",
        "Date": datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
    }
    
    header_lines = [f"{key}: {value}" for key, value in headers.items()]
    header = "\r\n".join(header_lines)
    response_body = str(data, "utf-8")
    response = f"HTTP/1.1 200 OK\r\n{header}\r\n\r\n{response_body}"

    return response

def readData(conn: socket.socket):
    recvData = bytes()
    data = conn.recv(1000000)

    recvData += data

    content = data.split(b"\r\n\r\n")[1]
    content_length = int(data.split(b"Content-Length: ")[1].split(b"\r\n")[0])
    recv_length = len(content)

    remain_length = content_length - recv_length

    while remain_length != 0:
        recv_length = 1000000

        if remain_length < 1000000:
            recv_length = remain_length

        data = conn.recv(recv_length)

        remain_length -= len(data)
        recvData += data
    
    return recvData
        

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()
print(f"Listening on port {PORT}...")

while True:
    conn, addr = s.accept()

    try:
        recvData = readData(conn)

        if not recvData:
            continue

        recvData = recvData.split(b"\r\n\r\ni=")

        if len(recvData) < 2:
            continue
        
        recvData = recvData[1]

        decryptedData = HappyCrypt.decrypt(recvData)

        happyPacket = HappyPacket()
        flag = happyPacket.parsePacket(decryptedData)

        if not flag:
            continue

        happyPacket.printPacket()

        responseData = happyPacket.getResponse()
        encryptedData = HappyCrypt.encrypt(responseData)

        sendData = generateResponse(encryptedData)

        conn.send(sendData.encode())
    except Exception as e:
        print(traceback.format_exc())

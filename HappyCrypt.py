import base64
from urllib import parse

class HappyCrypt:
    def decrypt(data: bytes) -> bytes:
        data += b'=' * (4 - len(data) % 4)
        decryptedData = bytearray(base64.b64decode(parse.unquote(data)))
        
        key = bytearray.fromhex("DD 33 99 CC")

        init = 0

        for i in range(0, len(decryptedData)):
            tmp = init ^ decryptedData[i] ^ key[i % 4]
            init = decryptedData[i]
            decryptedData[i] = tmp

        return bytes(decryptedData)

    def encrypt(data: bytes) -> bytes:
        encryptedData = bytearray()
        key = bytearray.fromhex("DD 33 99 CC")

        init = 0

        for i in range(0, len(data)):
            tmp = init ^ data[i] ^ key[i % 4]
            init = tmp
            encryptedData.append(tmp)

        encryptedData = base64.b64encode(encryptedData)

        return encryptedData

print("[Example]")
packet = b"3HY1zBEiu3eqmQDMyv5nq3ZF3BDN/merFnYxeaWWD8MeLbR4pZYPwx4ttHillg/DHi20eKWWD8MeLbR4"
print(f"Packet : {packet}")

dec_packet = HappyCrypt.decrypt(packet)
print(f"Decrypt Packet : {dec_packet}")

enc_packet = HappyCrypt.encrypt(dec_packet)
print(f"Encrypt Packet : {enc_packet}")

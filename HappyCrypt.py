import base64
from urllib import parse

class HappyCrypt:
    def __decrypt__(data: bytes, key: bytes) -> bytes:
        data += b'=' * (4 - len(data) % 4)
        decryptedData = bytearray(base64.b64decode(parse.unquote(data)))
        
        init = 0

        for i in range(0, len(decryptedData)):
            tmp = init ^ decryptedData[i] ^ key[i % 4]
            init = decryptedData[i]
            decryptedData[i] = tmp

        return bytes(decryptedData)

    def __encrypt__(data: bytes, key: bytes) -> bytes:
        encryptedData = bytearray()

        init = 0

        for i in range(0, len(data)):
            tmp = init ^ data[i] ^ key[i % 4]
            init = tmp
            encryptedData.append(tmp)

        encryptedData = base64.b64encode(encryptedData)

        return encryptedData

    def packet_decrypt(data: bytes) -> bytes:
        key = b"\xdd\x33\x99\xcc"
        return HappyCrypt.__decrypt__(data, key)

    def packet_encrypt(data: bytes) -> bytes:
        key = b"\xdd\x33\x99\xcc"
        return HappyCrypt.__encrypt__(data, key)
    
    def memload_decrypt(data: bytes) -> bytes:
        key = b"\x96\x50\x28\x44"
        return HappyCrypt.__decrypt__(data, key)
    
    def memload_encrypt(data: bytes) -> bytes:
        key = b"\x96\x50\x28\x44"
        return HappyCrypt.__encrypt__(data, key)
    
    def string_decode(data: bytes) -> str:
        key_data = data[0:4]
        target_data = bytearray(b'\00' + data[4:])

        for i in range(0, len(target_data) - 1):
            target_data[i] = key_data[i % 4] ^ target_data[i] ^ target_data[i + 1]
        
        return target_data[:-1].decode("utf-8")
    

# Packet/Registry
print("[Packet/Registry Example]")
packet = b"3HY1zBEiu3eqmQDMyv5nq3ZF3BDN/merFnYxeaWWD8MeLbR4pZYPwx4ttHillg/DHi20eKWWD8MeLbR4"
print(f"Packet : {packet}")

dec_packet = HappyCrypt.packet_decrypt(packet)
print(f"Decrypted Packet : {dec_packet}")

enc_packet = HappyCrypt.packet_encrypt(dec_packet)
print(f"Encrypted Packet : {enc_packet}")


# Memory
print("\n[Memory Example]")
enc_memory = b"[Input the memory data to be loaded]"
print(f"Encrypted Memory : {enc_memory}")

dec_memory = HappyCrypt.packet_decrypt(enc_memory)
print(f"Decrypted Memory : {dec_memory}")

enc_memory = HappyCrypt.packet_encrypt(dec_memory)
print(f"Encrypted Memory : {enc_memory}")


# String
print("\n[String Decode Example]")
encoded_data = b"\x86\x14\xA2\xED\xC5\xBD\x70\xEE\x0D\x51\x92\x11\xF3\x8B\x4C"
print(f"Encoded String : {encoded_data}")

dec_data = HappyCrypt.string_decode(encoded_data)
print(f"Decoded String : {dec_data}")

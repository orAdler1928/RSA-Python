class PublicKey:
    def __init__(self, n, e):
        self.n = n
        self.e = e

    def encrypt(self, msg: str) -> int:
        message_bytes = msg.encode("utf-8")
        message_int = int.from_bytes(message_bytes, byteorder="big")

        if message_int >= self.n:
            raise ValueError("Message is too long for the key size.")
        
        return pow(message_int, self.e, self.n)

class PrivateKey:
    def __init__(self, n: int, d: int):
        self.n = n
        self.d = d

    def decrypt(self, ciphertext: int) -> str:
        if not (0 <= ciphertext < self.n):
            raise ValueError("Ciphertext out of bounds (must be between 0 and n-1).")

        decrypted_int = pow(ciphertext, self.d, self.n)
        
        byte_length = (decrypted_int.bit_length() + 7) // 8
        decrypted_bytes = decrypted_int.to_bytes(byte_length, byteorder="big")
        
        try:
            return decrypted_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("Decrypted data is not valid UTF-8.") from e
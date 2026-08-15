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
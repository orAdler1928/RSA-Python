from src.rsa_core.keys import PrivateKey, PublicKey
from src.rsa_core.primes import PrimeGenerator


class RSAKeyGenerator:
    @staticmethod
    def generate_keypair(
        bits: int = 1024, e: int = 65537
    ) -> tuple[PublicKey, PrivateKey]:
        p = PrimeGenerator.generate_prime(bits=bits // 2, e=e)
        q = PrimeGenerator.generate_prime(bits=bits // 2, e=e)
        while p == q:
            q = PrimeGenerator.generate_prime(bits=bits // 2, e=e)

        n = p * q
        phi = (p - 1) * (q - 1)

        d = pow(e, -1, phi)

        return PublicKey(n=n, e=e), PrivateKey(n=n, d=d)

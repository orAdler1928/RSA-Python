import secrets


class PrimeGenerator:
    TRIAL_PRIMES = (
        3,
        5,
        7,
        11,
        13,
        17,
        19,
        23,
        29,
        31,
        37,
        41,
        43,
        47,
        53,
        59,
        61,
        67,
        71,
        73,
        79,
        83,
        89,
        97,
    )

    DETERMINISTIC_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41)

    @staticmethod
    def is_prime(n: int, k: int = 40) -> bool:
        if n < 2:
            return False

        if n == 2 or n in PrimeGenerator.TRIAL_PRIMES:
            return True

        if (n & 1) == 0:
            return False

        for p in PrimeGenerator.TRIAL_PRIMES:
            if n % p == 0:
                return False

        s = ((n - 1) & -(n - 1)).bit_length() - 1
        d = (n - 1) >> s

        def is_composite_base(a: int) -> bool:
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                return False
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    return False
            return True

        if n < 3_317_044_064_679_887_385_961_981:
            for a in PrimeGenerator.DETERMINISTIC_BASES:
                if n <= a:
                    break
                if is_composite_base(a):
                    return False
            return True

        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            if is_composite_base(a):
                return False

        return True

    @staticmethod
    def gcd(a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def generate_prime(bits: int = 1024, e: int = 65537) -> int:
        while True:
            candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1

            if PrimeGenerator.gcd(candidate - 1, e) == 1 and PrimeGenerator.is_prime(
                candidate
            ):
                return candidate

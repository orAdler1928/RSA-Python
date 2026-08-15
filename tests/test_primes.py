import pytest
from src.rsa_core.primes import PrimeGenerator


# ==========================================
# 1. בדיקות עבור אלגוריתם GCD (אוקלידס)
# ==========================================
@pytest.mark.parametrize(
    "a, b, expected",
    [
        (54, 24, 6),
        (101, 10, 1),  # מספרים זרים
        (65537, 65536, 1),  # מקרה קלאסי של RSA (e מול p - 1)
        (0, 5, 5),
        (5, 0, 5),
        (100, 100, 100),
    ],
)
def test_gcd(a, b, expected):
    assert PrimeGenerator.gcd(a, b) == expected


# ==========================================
# 2. בדיקות מקרי קצה ומספרים קטנים (is_prime)
# ==========================================
@pytest.mark.parametrize("n", [-10, -1, 0, 1])
def test_is_prime_invalid_and_small_numbers(n):
    """מספרים קטנים מ-2 אינם ראשוניים."""
    assert PrimeGenerator.is_prime(n) is False


def test_is_prime_two():
    """2 הוא המספר הראשוני הזוגי היחיד."""
    assert PrimeGenerator.is_prime(2) is True


@pytest.mark.parametrize("n", [4, 6, 8, 10, 100, 1000])
def test_is_prime_even_numbers(n):
    """מספרים זוגיים גדולים מ-2 אינם ראשוניים."""
    assert PrimeGenerator.is_prime(n) is False


# ==========================================
# 3. בדיקת ראשוניים ומורכבים מוכרים
# ==========================================
@pytest.mark.parametrize(
    "prime",
    [
        3,
        5,
        7,
        11,
        13,
        17,
        19,
        23,
        29,
        97,
        101,
        7919,  # ראשוני קטן
        104729,  # הראשוני ה-10,000
        2**31 - 1,  # מרסן M31 (ראשוני גדול יותר)
    ],
)
def test_is_prime_known_primes(prime):
    assert PrimeGenerator.is_prime(prime) is True


@pytest.mark.parametrize(
    "composite",
    [
        9,
        15,
        21,
        25,
        27,
        33,
        35,
        49,
        99,
        1001,  # 7 * 11 * 13
        104727,  # 3 * 34909
    ],
)
def test_is_prime_known_composites(composite):
    assert PrimeGenerator.is_prime(composite) is False


# ==========================================
# 4. מבחן מספרי קרמייקל (Carmichael Numbers)
# ==========================================
@pytest.mark.parametrize(
    "carmichael",
    [
        561,  # 3 * 11 * 17
        1105,  # 5 * 13 * 17
        1729,  # 7 * 13 * 19
        2465,  # 5 * 17 * 29
        2821,  # 7 * 7 * 31 (בערך)
        6601,  # 7 * 23 * 41
        8911,  # 7 * 19 * 67
    ],
)
def test_is_prime_carmichael_numbers(carmichael):
    """מספרים פריקים שעוברים את מבחן פרמה אך חייבים להיכשל במילר-רבין."""
    assert PrimeGenerator.is_prime(carmichael) is False


# ==========================================
# 5. בדיקת ייצור ראשוניים (generate_prime)
# ==========================================
@pytest.mark.parametrize("bits", [128, 256, 512])
def test_generate_prime_properties(bits):
    """בדיקה שהמספר המגורל עומד בכל דרישות ה-RSA."""
    e = 65537
    prime = PrimeGenerator.generate_prime(bits=bits, e=e)

    # 1. אורך ביטים מדויק
    assert prime.bit_length() == bits

    # 2. אי-זוגי
    assert prime % 2 != 0

    # 3. זר ל-e
    assert PrimeGenerator.gcd(prime - 1, e) == 1

    # 4. ראשוני אמיתי
    assert PrimeGenerator.is_prime(prime) is True


def test_generate_prime_randomness():
    """מוודא ששתי קריאות רצופות לא מייצרות את אותו מספר."""
    p1 = PrimeGenerator.generate_prime(bits=128)
    p2 = PrimeGenerator.generate_prime(bits=128)
    assert p1 != p2

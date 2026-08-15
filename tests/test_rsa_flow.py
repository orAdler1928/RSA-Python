from unittest.mock import patch

from src.rsa_core.generator import RSAKeyGenerator
from src.rsa_core.keys import PrivateKey, PublicKey


def test_generate_keypair_returns_correct_types():
    """בדיקה שהפונקציה מחזירה זוג אובייקטים מסוג PublicKey ו-PrivateKey."""
    pub, priv = RSAKeyGenerator.generate_keypair(bits=512)

    assert isinstance(pub, PublicKey)
    assert isinstance(priv, PrivateKey)


def test_generate_keypair_keys_share_same_n_and_correct_e():
    """בדיקה ששני המפתחות מחזיקים באותו n ושה-e תואם לקלט."""
    e = 65537
    pub, priv = RSAKeyGenerator.generate_keypair(bits=512, e=e)

    assert pub.n == priv.n
    assert pub.e == e


def test_generate_keypair_modulus_bit_length():
    """בדיקה שגודל המודולוס n קרוב מאוד לגודל הביטים המבוקש."""
    target_bits = 512
    pub, priv = RSAKeyGenerator.generate_keypair(bits=target_bits)

    # מאחר ש-p ו-q הם בגודל target_bits // 2, גודל n יהיה target_bits או target_bits - 1
    assert pub.n.bit_length() in (target_bits, target_bits - 1)


def test_generated_keypair_math_validity():
    """בדיקה מתמטית: הצפנה ופענוח של ערך אקראי מחזירים את המקור."""
    pub, priv = RSAKeyGenerator.generate_keypair(bits=512)

    msg = "Test Generated Key 🔑"
    ciphertext = pub.encrypt(msg)
    decrypted = priv.decrypt(ciphertext)

    assert decrypted == msg


def test_generate_keypair_handles_duplicate_prime():
    """בדיקה שהלולאה מתמודדת נכון ומייצרת q חדש אם התקבל p == q."""
    # נדמה מצב שבו generate_prime מחזיר בהתחלה את אותו מספר (61), ואז מספר חדש (53)
    mock_primes = [61, 61, 53]

    with patch(
        "src.rsa_core.generator.PrimeGenerator.generate_prime",
        side_effect=mock_primes,
    ):
        pub, priv = RSAKeyGenerator.generate_keypair(bits=16, e=17)

        # n אמור להיות 61 * 53 = 3233
        assert pub.n == 3233
        # phi = 60 * 52 = 3120 -> d = pow(17, -1, 3120) = 2753
        assert priv.d == 2753

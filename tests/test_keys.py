import pytest
from src.rsa_core.keys import PrivateKey, PublicKey


@pytest.fixture
def standard_key():
    """מפתח ציבורי לדוגמה (n = 3233 = 61 * 53, e = 17)."""
    return PublicKey(n=3233, e=17)


@pytest.fixture
def large_key():
    """מפתח גדול שמסוגל להכיל מחרוזות ארוכות יותר."""
    return PublicKey(n=2**256, e=65537)


@pytest.fixture
def rsa_key_pair():
    """
    יוצר זוג מפתחות תקני לבדיקות:
    p = 61, q = 53 -> n = 3233, phi = 3120
    e = 17 -> d = 2753 (כי 17 * 2753 % 3120 == 1)
    """
    pub = PublicKey(n=3233, e=17)
    priv = PrivateKey(n=3233, d=2753)
    return pub, priv

@pytest.fixture
def large_rsa_key_pair():
    """
    זוג מפתחות מבוסס ראשוניי מרסן מוכחים (p=2^521-1, q=2^607-1).
    n הוא באורך 1128 ביט ומכיל מחרוזות של עד 140 בתים.
    """
    p = (1 << 521) - 1
    q = (1 << 607) - 1

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)

    return PublicKey(n=n, e=e), PrivateKey(n=n, d=d)
# --- טסטים עבור הצפנה (PublicKey) ---


def test_encrypt_valid_short_message(standard_key):
    """בדיקת הצפנה של מחרוזת קצרה תקינה."""
    msg = "A"
    expected_int = 65
    expected_encrypted = pow(expected_int, 17, 3233)

    result = standard_key.encrypt(msg)
    assert isinstance(result, int)
    assert result == expected_encrypted


def test_encrypt_empty_string(standard_key):
    """בדיקת הצפנה של מחרוזת ריקה (מומרת ל-0)."""
    result = standard_key.encrypt("")
    assert result == 0


def test_encrypt_unicode_characters(large_key):
    """בדיקה שהקידוד ל-UTF-8 עובד נכון גם עם עברית ואימוג'י."""
    msg = "שלום 🚀"
    msg_int = int.from_bytes(msg.encode("utf-8"), byteorder="big")
    expected = pow(msg_int, large_key.e, large_key.n)

    result = large_key.encrypt(msg)
    assert result == expected


def test_encrypt_message_too_long_raises_error(standard_key):
    """בדיקה שנזרקת שגיאת ValueError כשההודעה גדולה או שווה ל-n."""
    long_msg = "AB"
    with pytest.raises(ValueError, match="Message is too long for the key size."):
        standard_key.encrypt(long_msg)


def test_encrypt_deterministic_output(standard_key):
    """הצפנת RSA ללא Padding אמורה להיות דטרמיניסטית."""
    msg = "B"
    res1 = standard_key.encrypt(msg)
    res2 = standard_key.encrypt(msg)
    assert res1 == res2


@pytest.mark.parametrize("msg", ["a", "1", "\n", " "])
def test_encrypt_various_single_chars(standard_key, msg):
    """בדיקה פרמטרית עבור תווים שונים בגודל בית יחיד."""
    msg_int = int.from_bytes(msg.encode("utf-8"), byteorder="big")
    expected = pow(msg_int, standard_key.e, standard_key.n)
    assert standard_key.encrypt(msg) == expected


# --- טסטים עבור פענוח וסבב מלא (PrivateKey & Round-trip) ---


def test_decrypt_valid_ciphertext(rsa_key_pair):
    """בדיקת פענוח של הצפנה בסיסית."""
    pub, priv = rsa_key_pair
    msg = "A"

    ciphertext = pub.encrypt(msg)
    decrypted = priv.decrypt(ciphertext)
    assert decrypted == msg


def test_decrypt_empty_string(rsa_key_pair):
    """בדיקת פענוח של מחרוזת ריקה (הצפנה שמחזירה 0)."""
    pub, priv = rsa_key_pair

    ciphertext = pub.encrypt("")
    decrypted = priv.decrypt(ciphertext)
    assert decrypted == ""


@pytest.mark.parametrize(
    "msg",
    [
        "Hello",
        "שלום",
        "RSA 2026 🚀",
        "Text with\nnewlines & symbols: !@#$%",
    ],
)
def test_full_roundtrip_encryption_decryption(large_rsa_key_pair, msg):
    """בדיקה שהצפנה ופענוח עוקבים מחזירים תמיד את הטקסט המקורי."""
    pub, priv = large_rsa_key_pair

    ciphertext = pub.encrypt(msg)
    decrypted = priv.decrypt(ciphertext)
    assert decrypted == msg


def test_decrypt_ciphertext_out_of_bounds_raises_error(rsa_key_pair):
    """בדיקה שנזרקת שגיאה כאשר הטקסט המוצפן חורג מגבולות n או שלילי."""
    _, priv = rsa_key_pair

    with pytest.raises(ValueError, match="Ciphertext out of bounds"):
        priv.decrypt(-1)

    with pytest.raises(ValueError, match="Ciphertext out of bounds"):
        priv.decrypt(priv.n)

    with pytest.raises(ValueError, match="Ciphertext out of bounds"):
        priv.decrypt(priv.n + 100)


def test_decrypt_invalid_utf8_raises_error(rsa_key_pair):
    """בדיקה שנזרקת שגיאה מותאמת כאשר המידע המפוענח אינו UTF-8 תקין."""
    _, priv = rsa_key_pair

    invalid_utf8_int = 0xFF
    e = 17
    invalid_ciphertext = pow(invalid_utf8_int, e, priv.n)

    with pytest.raises(ValueError, match="Decrypted data is not valid UTF-8."):
        priv.decrypt(invalid_ciphertext)
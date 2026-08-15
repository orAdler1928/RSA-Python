import pytest
from src.rsa_core.keys import PublicKey


# מניחים שהמחלקה מיובאת או מוגדרת כאן
# from rsa_module import PublicKey


@pytest.fixture
def standard_key():
    """מפתח ציבורי לדוגמה (n = 3233 = 61 * 53, e = 17)."""
    return PublicKey(n=3233, e=17)


@pytest.fixture
def large_key():
    """מפתח גדול שמסוגל להכיל מחרוזות ארוכות יותר."""
    # n = 2^256 - ערך גדול לדוגמה
    return PublicKey(n=2**256, e=65537)


def test_encrypt_valid_short_message(standard_key):
    """בדיקת הצפנה של מחרוזת קצרה תקינה."""
    msg = "A"  # 'A' ב-ASCII/UTF-8 זה 65
    expected_int = 65
    expected_encrypted = pow(expected_int, 17, 3233)
    
    result = standard_key.encrypt(msg)
    
    assert isinstance(result, int)
    assert result == expected_encrypted


def test_encrypt_empty_string(standard_key):
    """בדיקת הצפנה של מחרוזת ריקה (מומרת ל-0)."""
    # 0 ** e % n == 0
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
    # 'AB' ב-bytes זה [65, 66] -> 65 * 256 + 66 = 16706 > 3233
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
import content_sqid
import pytest
from content_sqid import _hex_digest_to_int, hex_digest_to_sqid


@pytest.fixture()
def no_hash_limit():
    """Remove the limitation on the length of the contenthash that is consumed temporarily"""
    old = content_sqid.HASH_SUBSTRING_LENGTH
    content_sqid.HASH_SUBSTRING_LENGTH = 999
    yield None
    content_sqid.HASH_SUBSTRING_LENGTH = old


def test_hex_to_int():
    """
    These values shouldn't change -- if they do, it means our hashes aren't stable.
    Changing the alphabet will change them.
    """
    assert _hex_digest_to_int("deadbeef") == 3735928559
    assert hex_digest_to_sqid("deadbeef") == "hdgcqtcnm"


def test_min_length():
    """Low-value hashes are an acceptable length"""
    assert hex_digest_to_sqid("0") == "xcsrdnmp"


def test_max_value():
    """This should be the largest value we can ever get"""
    assert hex_digest_to_sqid("ffffffffffffffffffffffffffffff") == "tspwbpshvpklr"


def test_hex_truncation():
    """A large hex value works and is the same value as the truncated version"""
    assert _hex_digest_to_int(
        "2597c39e63c20d69dc0cb189a88a8ab127c335cdcbf1d9ee43de3f711002de52"
    ) == _hex_digest_to_int("2597c39e63c2")


def test_demo_limit_of_truncation(no_hash_limit):
    """Demonstrate that without a limit to the length of a hash, a 16-character hash can fail"""
    assert hex_digest_to_sqid("7fffffffffffffff")
    with pytest.raises(ValueError):
        assert hex_digest_to_sqid("8000000000000000")

from sqids import Sqids

# HASH_SUBSTRING_LENGTH must be strictly less than 16;
# for 16, hashes starting with 8 have a number too large to be turned into sqid.
# (under the hood, sqids are numbers less than the hex value
# 8000 0000 0000 0000 and do not exist for numbers higher than that)
HASH_SUBSTRING_LENGTH = 12

# SQID_ALPHABET contains no vowels, including y
SQID_ALPHABET = "bcdfghjklmnpqrstvwxz"
SQID_MIN_LENGTH = 8

sqids = Sqids(alphabet=SQID_ALPHABET, min_length=SQID_MIN_LENGTH)


def _hex_digest_to_int(digest_string: str) -> int:
    return int(digest_string.encode("utf-8")[:HASH_SUBSTRING_LENGTH], 16)


def hex_digest_to_sqid(digest_string: str) -> str:
    num = _hex_digest_to_int(digest_string)
    return sqids.encode([num])

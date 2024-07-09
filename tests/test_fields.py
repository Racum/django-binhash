import sys

from django.core.exceptions import ValidationError
from django.db import connection
import pytest

from .models import ALLHashes, Table, TableWithBadDefaultValue, TableWithGoodDefaultValue

ERROR_VALUE = 'Enter a valid TestHash (hexadecimal string with 8 bytes).'


@pytest.fixture(autouse=True)
def enable_db_access(db):
    pass


def test_good_hash():
    assert Table.objects.create(hashed='c7a1a2b5').hashed == 'c7a1a2b5'


def test_db_internal_value():
    Table.objects.all().delete()
    Table.objects.create(hashed='c7a1a2b5')
    with connection.cursor() as cursor:
        cursor.execute('SELECT hashed FROM tests_Table;')
        row = cursor.fetchone()
        assert len(row[0]) == 4  # Not 8, as the input hex-string.
        if sys.version_info.major >= 3:
            assert row[0] == b'\xc7\xa1\xa2\xb5'  # 'c7a1a2b5' into binary.
        else:
            assert bytes(row[0]) == bytes(b'\xc7\xa1\xa2\xb5')  # 'c7a1a2b5' into binary.


def test_good_hash_uppercase_in_lowercase_out():
    instance = Table.objects.create(hashed='C7A1A2B5')
    instance.refresh_from_db()
    assert instance.hashed == 'c7a1a2b5'


def test_bad_hash_with_wrong_size():
    with pytest.raises(ValidationError) as e:
        Table.objects.create(hashed='c7a1')
    assert e.value.message == ERROR_VALUE


def test_bad_hash_with_invalid_hex():
    with pytest.raises(ValidationError) as e:
        Table.objects.create(hashed='gggggggg')
    assert e.value.message == ERROR_VALUE


@pytest.mark.parametrize(
    'hashed',
    [
        1000000,
        b'1000000',
        ['a', 'list'],
        {'a': 'dict'},
        True,
        False,
    ],
)
def test_bad_hash_wrong_types(hashed):
    with pytest.raises(ValidationError) as e:
        Table.objects.create(hashed=hashed)
    assert e.value.message == ERROR_VALUE


def test_empty_hash():
    assert Table.objects.create().hashed is None


def test_empty_string_hash():
    instance = Table.objects.create(hashed='')
    instance.refresh_from_db()
    assert instance.hashed is None


def test_good_default_hash():
    assert TableWithGoodDefaultValue.objects.create().hashed == '12345678'


def test_bad_default_hash():
    with pytest.raises(ValidationError) as e:
        TableWithBadDefaultValue.objects.create()
    assert e.value.message == ERROR_VALUE


def test_get_instance_via_hash():
    Table.objects.create(hashed='1234abcd')
    assert Table.objects.get(hashed='1234abcd').hashed == '1234abcd'


def test_filter_instance_via_hash():
    Table.objects.create(hashed='5678abcd')
    assert Table.objects.filter(hashed='5678abcd').count() == 1


def test_update_hash():
    instance = Table.objects.create(hashed='0000abcd')
    instance.hashed = '1111abcd'
    instance.save()
    assert Table.objects.filter(hashed='0000abcd').count() == 0  # No more 0000abcd.
    assert Table.objects.filter(hashed='1111abcd').count() == 1


@pytest.mark.parametrize(
    'field, hash, error',
    [
        (
            'md5',
            'd41d8cd98f00b204e9800998ecf8427e',
            'Enter a valid MD5 (hexadecimal string with 32 bytes).',
        ),
        (
            'sha1',
            'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'Enter a valid SHA-1 (hexadecimal string with 40 bytes).',
        ),
        (
            'sha224',
            'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
            'Enter a valid SHA-224 (hexadecimal string with 56 bytes).',
        ),
        (
            'sha256',
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'Enter a valid SHA-256 (hexadecimal string with 64 bytes).',
        ),
        (
            'sha384',
            '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
            'Enter a valid SHA-384 (hexadecimal string with 96 bytes).',
        ),
        (
            'sha512',
            'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
            '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
            'Enter a valid SHA-512 (hexadecimal string with 128 bytes).',
        ),
        (
            'sha3_224',
            '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7',
            'Enter a valid SHA3-224 (hexadecimal string with 56 bytes).',
        ),
        (
            'sha3_256',
            'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
            'Enter a valid SHA3-256 (hexadecimal string with 64 bytes).',
        ),
        (
            'sha3_384',
            '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004',
            'Enter a valid SHA3-384 (hexadecimal string with 96 bytes).',
        ),
        (
            'sha3_512',
            'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6'
            '15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
            'Enter a valid SHA3-512 (hexadecimal string with 128 bytes).',
        ),
        (
            'shake128',
            '7f9c2ba4e88f827d616045507605853e',
            'Enter a valid SHAKE128 (hexadecimal string with 32 bytes).',
        ),
        (
            'shake256',
            '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f',
            'Enter a valid SHAKE256 (hexadecimal string with 64 bytes).',
        ),
        (
            'shake512',
            'ae1b4eea1eaf5ea633e66045f03ff11b8b7d3193119075442117bd786dfd939f'
            '25a53a30fae503488d42683c1917b3964f6b1cf5d27c2b40cbaf53c5b749666a',
            'Enter a valid SHAKE512 (hexadecimal string with 128 bytes).',
        ),
    ],
)
def test_specific_fields_valid(field, hash, error):
    # Valid case:
    instance = ALLHashes.objects.create(**{field: hash})
    instance.refresh_from_db()
    assert getattr(instance, field) == hash
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT {field} FROM tests_ALLHashes;')
        data_on_db = cursor.fetchone()[0]
    assert len(data_on_db) == len(hash) / 2

    # Invalid case:
    with pytest.raises(ValidationError) as e:
        ALLHashes.objects.create(**{field: 'badca5e'})
    assert e.value.message == error

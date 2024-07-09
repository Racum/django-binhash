from django.db import models

from binhash import (
    BinaryHashField,
    MD5Field,
    SHA1Field,
    SHA224Field,
    SHA256Field,
    SHA384Field,
    SHA512Field,
    SHA3_224Field,
    SHA3_256Field,
    SHA3_384Field,
    SHA3_512Field,
    SHAKE128Field,
    SHAKE256Field,
    SHAKE512Field,
)


class TestField(BinaryHashField):
    algorithm = 'TestHash'
    hex_length = 8


class Table(models.Model):
    hashed = TestField(null=True)


class TableWithGoodDefaultValue(models.Model):
    hashed = TestField(default='12345678')


class TableWithBadDefaultValue(models.Model):
    hashed = TestField(default='gggggggg')


class ALLHashes(models.Model):
    md5 = MD5Field(null=True)
    sha1 = SHA1Field(null=True)
    sha224 = SHA224Field(null=True)
    sha256 = SHA256Field(null=True)
    sha384 = SHA384Field(null=True)
    sha512 = SHA512Field(null=True)
    sha3_224 = SHA3_224Field(null=True)
    sha3_256 = SHA3_256Field(null=True)
    sha3_384 = SHA3_384Field(null=True)
    sha3_512 = SHA3_512Field(null=True)
    shake128 = SHAKE128Field(null=True)
    shake256 = SHAKE256Field(null=True)
    shake512 = SHAKE512Field(null=True)

from abc import ABC
import binascii
import re

from django.core.exceptions import ValidationError
from django.core.validators import MaxLengthValidator
from django.db.models.fields import Field

HEXADECIMAL_VALUES = re.compile(r'^[0-9a-fA-F]+\Z')


class BinaryHashField(ABC, Field):
    description = 'Hash data saved as binary'
    empty_values = (None, '')

    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = self.hex_length
        super().__init__(*args, **kwargs)
        self.validators.append(MaxLengthValidator(self.max_length))

    def get_internal_type(self):
        return 'BinaryField'

    def _hex_is_valid(self, value):
        if isinstance(value, str) and len(value) == self.hex_length and HEXADECIMAL_VALUES.search(str(value)):
            return value
        else:
            raise ValidationError(f'Enter a valid {self.algorithm} (hexadecimal string with {self.hex_length} bytes).')

    def clean(self, value, model_instance):
        return self._hex_is_valid(value)

    def hex_to_bytes(self, value):
        if value is None:
            return value
        value = self._hex_is_valid(value)
        return binascii.unhexlify(value)

    def get_db_prep_value(self, value, connection, prepared=False):
        value = super().get_db_prep_value(value, connection, prepared)
        if value not in self.empty_values:
            return connection.Database.Binary(self.hex_to_bytes(value))

    def from_db_value(self, value, expression, connection, context=None):
        if value not in self.empty_values:
            return binascii.hexlify(value).decode('ascii')

    def formfield(self, **kwargs):
        return super().formfield(max_length=self.max_length)


class MD5Field(BinaryHashField):
    description = 'MD5 hash data saved as binary'
    algorithm = 'MD5'
    hex_length = 32


class SHA1Field(BinaryHashField):
    description = 'SHA-1 hash data saved as binary'
    algorithm = 'SHA-1'
    hex_length = 40


class SHA224Field(BinaryHashField):
    description = 'SHA-224 hash data saved as binary'
    algorithm = 'SHA-224'
    hex_length = 56


class SHA256Field(BinaryHashField):
    description = 'SHA-256 hash data saved as binary'
    algorithm = 'SHA-256'
    hex_length = 64


class SHA384Field(BinaryHashField):
    description = 'SHA-384 hash data saved as binary'
    algorithm = 'SHA-384'
    hex_length = 96


class SHA512Field(BinaryHashField):
    description = 'SHA-512 hash data saved as binary'
    algorithm = 'SHA-512'
    hex_length = 128


class SHA3_224Field(BinaryHashField):
    description = 'SHA3-224 hash data saved as binary'
    algorithm = 'SHA3-224'
    hex_length = 56


class SHA3_256Field(BinaryHashField):
    description = 'SHA3-256 hash data saved as binary'
    algorithm = 'SHA3-256'
    hex_length = 64


class SHA3_384Field(BinaryHashField):
    description = 'SHA3-384 hash data saved as binary'
    algorithm = 'SHA3-384'
    hex_length = 96


class SHA3_512Field(BinaryHashField):
    description = 'SHA3-512 hash data saved as binary'
    algorithm = 'SHA3-512'
    hex_length = 128


class SHAKE128Field(BinaryHashField):
    description = 'SHAKE128 hash data saved as binary'
    algorithm = 'SHAKE128'
    hex_length = 32


class SHAKE256Field(BinaryHashField):
    description = 'SHAKE256 hash data saved as binary'
    algorithm = 'SHAKE256'
    hex_length = 64


class SHAKE512Field(BinaryHashField):
    description = 'SHAKE512 hash data saved as binary'
    algorithm = 'SHAKE512'
    hex_length = 128

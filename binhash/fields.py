# -*- coding: utf-8 -*-

import re
import binascii

from django.core import validators
from django.db.models.fields import Field
from django.core.exceptions import ValidationError


HEXADECIMAL_VALUES = re.compile(r'^[0-9a-fA-F]+\Z')
try:
    basestring  # Python 3 has no basestring
except NameError:
    basestring = str


class BinaryHashField(Field):
    description = 'Hash data saved as binary'
    empty_values = (None, '')

    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = self.hex_length
        super(BinaryHashField, self).__init__(*args, **kwargs)
        self.validators.append(validators.MaxLengthValidator(self.max_length))

    def get_internal_type(self):
        return "BinaryField"

    def hex_to_bytes(self, value):
        if value is None:
            return value
        elif isinstance(value, basestring) \
                and len(value) == self.hex_length \
                and HEXADECIMAL_VALUES.search(str(value)):
            return binascii.unhexlify(value)
        else:
            message_tpl = 'Enter a valid {alg} (hexadecimal string with {size} bytes).'
            message = message_tpl.format(alg=self.algorithm, size=self.hex_length)
            raise ValidationError(message)

    def get_db_prep_value(self, value, connection, prepared=False):
        value = super(BinaryHashField, self).get_db_prep_value(value, connection, prepared)
        if value not in self.empty_values:
            return connection.Database.Binary(self.hex_to_bytes(value))

    def from_db_value(self, value, expression, connection, context):
        if value not in self.empty_values:
            return binascii.hexlify(value).decode('ascii')

    def to_python(self, value):
        self.hex_to_bytes(value)
        return value

    def get_default(self):
        if self.has_default() and not callable(self.default):
            self.hex_to_bytes(self.default)
            return self.default
        default = super(BinaryHashField, self).get_default()
        return default

    def formfield(self, **kwargs):
        return super(BinaryHashField, self).formfield(max_length=self.max_length)


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

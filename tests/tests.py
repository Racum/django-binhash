# -*- coding: utf-8 -*-

import sys

from django.core.exceptions import ValidationError
from django.db import models, connection
from django.test import TestCase

from binhash import (BinaryHashField, MD5Field, SHA1Field,
                     SHA224Field, SHA256Field, SHA384Field, SHA512Field)


class TestField(BinaryHashField):
    algorithm = 'TestHash'
    hex_lenght = 8


class TestTable(models.Model):
    hashed = TestField(null=True)


class TestTableWithGoodDefaultValue(models.Model):
    hashed = TestField(default='12345678')


class TestTableWithBadDefaultValue(models.Model):
    hashed = TestField(default='gggggggg')


class BinaryHashFieldsTest(TestCase):

    error_value = 'Enter a valid TestHash (hexadecimal string with 8 bytes).'

    def test_good_hash(self):
        instance = TestTable.objects.create(hashed='c7a1a2b5')
        instance.refresh_from_db()
        self.assertEqual(instance.hashed, 'c7a1a2b5')

    def test_db_internal_value(self):
        TestTable.objects.all().delete()
        TestTable.objects.create(hashed='c7a1a2b5')
        with connection.cursor() as cursor:
            cursor.execute('SELECT hashed FROM tests_testtable;')
            row = cursor.fetchone()
            self.assertEqual(len(row[0]), 4)  # Not 8, as the input hex-string.
            if sys.version_info.major >= 3:
                self.assertEqual(row[0], b'\xc7\xa1\xa2\xb5')  # 'c7a1a2b5' into binary.
            else:
                self.assertEqual(bytes(row[0]), bytes(b'\xc7\xa1\xa2\xb5'))  # 'c7a1a2b5' into binary.

    def test_good_hash_uppercase_in_lowercase_out(self):
        instance = TestTable.objects.create(hashed='C7A1A2B5')
        instance.refresh_from_db()
        self.assertEqual(instance.hashed, 'c7a1a2b5')

    def test_bad_hash_with_wrong_size(self):
        with self.assertRaisesMessage(ValidationError, self.error_value):
            TestTable.objects.create(hashed='c7a1')

    def test_bad_hash_with_invalid_hex(self):
        with self.assertRaisesMessage(ValidationError, self.error_value):
            TestTable.objects.create(hashed='gggggggg')

    def test_bad_hash_wrong_types(self):
        with self.assertRaisesMessage(ValidationError, self.error_value):
            TestTable.objects.create(hashed=1000000)
        with self.assertRaisesMessage(ValidationError, self.error_value):
            TestTable.objects.create(hashed=b'1000000')
        with self.assertRaisesMessage(ValidationError, self.error_value):
            TestTable.objects.create(hashed=['a', 'list'])
        with self.assertRaisesMessage(ValidationError, self.error_value):
            TestTable.objects.create(hashed={'a': 'dict'})
        with self.assertRaisesMessage(ValidationError, self.error_value):
            TestTable.objects.create(hashed=True)
        with self.assertRaisesMessage(ValidationError, self.error_value):
            TestTable.objects.create(hashed=False)

    def test_empty_hash(self):
        instance = TestTable.objects.create()
        self.assertEqual(instance.hashed, None)

    def test_empty_string_hash(self):
        instance = TestTable.objects.create(hashed='')
        instance.refresh_from_db()
        self.assertEqual(instance.hashed, None)

    def test_good_default_hash(self):
        instance = TestTableWithGoodDefaultValue.objects.create()
        self.assertEqual(instance.hashed, '12345678')

    def test_bad_default_hash(self):
        with self.assertRaisesMessage(ValidationError, self.error_value):
            TestTableWithBadDefaultValue.objects.create()

    def test_get_instance_via_hash(self):
        TestTable.objects.create(hashed='1234abcd')
        instance = TestTable.objects.get(hashed='1234abcd')
        self.assertEqual(instance.hashed, '1234abcd')

    def test_filter_instance_via_hash(self):
        TestTable.objects.create(hashed='5678abcd')
        self.assertEqual(TestTable.objects.filter(hashed='5678abcd').count(), 1)

    def test_update_hash(self):
        instance = TestTable.objects.create(hashed='0000abcd')
        self.assertEqual(instance.hashed, '0000abcd')
        instance.hashed = '1111abcd'
        instance.save()
        self.assertEqual(TestTable.objects.filter(hashed='0000abcd').count(), 0)  # No more 0000abcd.
        self.assertEqual(TestTable.objects.get(hashed='1111abcd').hashed, '1111abcd')


class ALLHashes(models.Model):
    md5 = MD5Field(null=True)
    sha1 = SHA1Field(null=True)
    sha224 = SHA224Field(null=True)
    sha256 = SHA256Field(null=True)
    sha384 = SHA384Field(null=True)
    sha512 = SHA512Field(null=True)


class SpecificFieldsTest(TestCase):

    scenarios = [
        {'field': 'md5',
         'hash': 'd3fd9a3736b650b6139e39948df08121',
         'error': 'Enter a valid MD5 (hexadecimal string with 32 bytes).'},
        {'field': 'sha1',
         'hash': 'c45e44957a17c19473c8851b11a8652917525f09',
         'error': 'Enter a valid SHA-1 (hexadecimal string with 40 bytes).'},
        {'field': 'sha224',
         'hash': 'b1b425d79664108e5dce8ea177b0e0caa07d4555c9c00724ae8d4aa9',
         'error': 'Enter a valid SHA-224 (hexadecimal string with 56 bytes).'},
        {'field': 'sha256',
         'hash': 'fe16290ab4fbeafc0b21c0fec57bc53b6b10f276495da989e9a5afe69a40bca6',
         'error': 'Enter a valid SHA-256 (hexadecimal string with 64 bytes).'},
        {'field': 'sha384',
         'hash': '7bb38353dcfcc263fe340398d599210deea497436fe1f2c2'
                 '6c7ae9f1f5cf9f814e0b1569ed52c8f528ba6a90b2c6ab01',
         'error': 'Enter a valid SHA-384 (hexadecimal string with 96 bytes).'},
        {'field': 'sha512',
         'hash': '71c7c50dcef0a6ee0eb11c02b18828acfbc775c7a0405af43493987dd766723a'
                 'f64d15d728fc3ed42066e0ae4ba3ed633f9df33d50daf92f418eb39a0c34206f',
         'error': 'Enter a valid SHA-512 (hexadecimal string with 128 bytes).'}
    ]

    def test_good_cases(self):

        def run_scenario(scenario):
            instance = ALLHashes.objects.create(**{scenario['field']: scenario['hash']})
            instance.refresh_from_db()
            self.assertEqual(getattr(instance, scenario['field']), scenario['hash'])

        for scenario in self.scenarios:
            if hasattr(TestCase, 'subTest'):
                with self.subTest(scenario=scenario):
                    run_scenario(scenario)
            else:
                run_scenario(scenario)

    def test_bad_cases(self):

        def run_scenario(scenario):
            with self.assertRaisesMessage(ValidationError, scenario['error']):
                ALLHashes.objects.create(**{scenario['field']: 'badca5e'})

        for scenario in self.scenarios:
            if hasattr(TestCase, 'subTest'):
                with self.subTest(scenario=scenario):
                    run_scenario(scenario)
            else:
                run_scenario(scenario)

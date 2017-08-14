Django Binary Hash Fields
=========================

Work with hexadecimal, store in binary, using half of the data size.

Installation
------------

Just install via ``pip``:

::

    pip install django-binhash

And add to your apps on ``settings.py``:

.. code:: python

    INSTALLED_APPS = [
        # Django apps
       'binhash',
        # Your apps
    ]

Compatibility
-------------

Environments
~~~~~~~~~~~~

Tested under Python from 3.3 to 3.6 and also *Legacy Python* (2.7).

Tested under Django 1.8 to 1.11, but it can possibly run in versions way
older, since the fields structure is stable for a long time.

Databases
~~~~~~~~~

At the version ``0.1.0`` it was only tested on SQLite, but if should
work fine in all databases officially supported by Django.

Formats
~~~~~~~

-  MD5

   -  ``MD5Field``

-  SHA-1

   -  ``SHA1Field``

-  SHA-2

   -  ``SHA224Field``
   -  ``SHA256Field``
   -  ``SHA384Field``
   -  ``SHA512Field``

Usage
-----

Just import and set some fields:

.. code:: python

    from django.db import models
    from binhash import (MD5Field, SHA1Field, SHA256Field)

    class ISOFile(models.Model):
        name = models.CharField('Name', max_length=30)
        url = models.URLField('URL')
        md5sum = MD5Field('MD5 Checksum')
        sha1sum = SHA1Field('SHA-1 Checksum')
        sha256sum = SHA256Field('SHA-256 Checksum')

Than, proceed using them like CharFields:

.. code:: python

    # Create normaly as if the fields were strings:
    ISOFile.objects.create(name='Ubuntu Server 17.04',
                           md5sum='d02df11b4a7318b7250824f6d0bab9c0',
                           sha1sum='bc5fb639724b5cd90eb739845f246e2c564b0dd8',
                           sha256sum='632e64dde9a7da27fa96bea4d2cf78f0'
                                     '51065c6becc0d0f728aabfc091396256')

    # Fetch by string is also supported:
    ubuntu = ISOFile.objects.get(md5sum='d02df11b4a7318b7250824f6d0bab9c0')

    # Everything works as expected on the application side:
    print(ubuntu.sha1sum)  # Shows bc5fb639724b5cd90eb739845f246e2c564b0dd8
    print(type(ubuntu.sha1sum))  # Shows <class 'str'>

If you are feeling skeptical, check the database:

::

    $ ./manage.py dbshell
    sqlite> .header on
    sqlite> .mode column
    sqlite> select hex(sha1sum) hex_sha1,
       ...>        length(hex(sha1sum)) size_if_this_was_varchar,
       ...>        length(sha1sum) actual_size
       ...> from downloads_isofile;
    hex_sha1                                  size_if_this_was_varchar  actual_size
    ----------------------------------------  ------------------------  -----------
    BC5FB639724B5CD90EB739845F246E2C564B0DD8  40                        20

License
-------

This library is released under the **3-Clause BSD License**.

**tl;dr**: *"free to use as long as you credit me"*.

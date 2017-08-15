#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open('pypi_description.rst') as readme_file:
    pypi_description = readme_file.read()

setup(
    name='django-binhash',
    version='0.1.1',
    description='Work with hexadecimal, store in binary, using half of the data size.',
    long_description=pypi_description,
    author="Ronaldo Racum",
    author_email='ronaldo@racum.com',
    url='https://github.com/racum/django-binhash',
    packages=find_packages(include=['django-binhash']),
    include_package_data=True,
    install_requires=['django'],
    license="BSD-3-Clause",
    zip_safe=False,
    keywords='binhash',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    test_suite='runtests.runtests',
)

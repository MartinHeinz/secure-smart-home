# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='Secure Smart Home',
    version='0.1.0',
    description='Privacy friendly cloud framework for digital assistants',
    long_description=readme,
    author='Martin Heinz',
    author_email='martin7.heinz@gmail.com',
    url='',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)


#!/usr/bin/env python
from setuptools import setup

with open('README.md') as f:
	long_description = f.read()

setup(name='pyxbe',
      version='1.0.1',
      description='Library to work with XBE files',
      long_description=long_description,
      long_description_content_type='text/markdown',
      author='Matt Borgerson',
      author_email='contact@mborgerson.com',
      url='https://github.com/mborgerson/pyxbe',
      license='MIT',
      packages=['xbe'],
     )

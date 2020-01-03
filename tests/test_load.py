#!/usr/bin/env python
import unittest
from xbe import Xbe
import os.path

class BasicLoadTestCase(unittest.TestCase):
	"""Test loading an XBE from a file"""

	def test_load_from_file(self):
		path = os.path.join('xbefiles', 'triangle.xbe')
		xbe = Xbe.from_file(path)
		self.assertTrue(xbe.title_name == 'triangle')

if __name__ == '__main__':
	unittest.main()

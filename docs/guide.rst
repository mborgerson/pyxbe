Guide
=====

Installation
------------
This package can be installed on Linux, macOS, and Windows platforms for recent (3.8+) versions of Python. The latest release can be installed from PyPI using ``pip``:

.. code:: bash

   pip install pyxbe

The very latest development version can be installed from GitHub via:

.. code:: bash

   pip install --user https://github.com/mborgerson/pyxbe/archive/refs/heads/master.zip

Usage Example
-------------

.. ipython::

   In [0]: from xbe import Xbe

   In [0]: xbe = Xbe.from_file('../tests/xbefiles/triangle.xbe')

   In [0]: # Get basic info about the XBE
      ...: xbe.title_name

   In [0]: hex(xbe.entry_addr)

   In [0]: # Get detailed info from XBE data structures
      ...: xbe.header

   In [0]: # List sections
      ...: xbe.sections

   In [0]: # Get detailed section info
      ...: xbe.sections['.text'].header

   In [0]: # Get section data
      ...: len(xbe.sections['.text'].data)

Command Line Usage Example
--------------------------

To dump out various details about the XBE file, you can invoke the
module:

.. code:: bash

   python3 -m xbe default.xbe

To extract embedded title and save images in the XBE:

.. code:: bash

   python3 -m xbe --extract-images default.xbe

To convert ``.xbx`` images to BMP:

.. code:: bash

   python3 -m xbe --xbx-to-bmp *.xbx

pyxbe ![CI Status](https://github.com/mborgerson/pyxbe/workflows/Tests/badge.svg?branch=master)
=====
Python 3 library to work with `.xbe` files, the [executable file format for the
original Xbox game console](http://xboxdevwiki.net/Xbe).

Install
-------
Install with PIP:

```bash
python3 -m pip install --user git+https://github.com/mborgerson/pyxbe
```

Usage
-----

### As a command-line tool

To dump out various details about the XBE file, you can invoke the module:

```bash
$ python3 -m xbe default.xbe
```

To extract embedded title and save images in the XBE:

```bash
$ python -m xbe --extract-images default.xbe
```

To convert `.xbx` images to BMP:

```bash
$ python -m xbe --xbx-to-bmp *.xbx
```

### As a library

```python
# Import
from pprint import pprint
from xbe import Xbe
xbe = Xbe.from_file('default.xbe')

# Get basic info about the XBE
xbe.title_name
# 'Halo'
hex(xbe.entry_addr)
# '0x15cc9'

# Get detailed info from XBE data structures
xbe.header
# magic:                       0x48454258
# signature:
#   dc 2c 66 4f 44 18 c6 43 81 f1 c9 51 34 18 8d f4
#   0f 37 e0 19 79 c4 5a 10 cd 34 6a 72 a4 0b 90 83
#   b0 f3 4e 11 33 53 49 d2 db 93 cc a9 ac cc bd 01
#   8e 4f 3e 94 69 79 83 cb 44 05 04 76 34 95 11 01
#   a8 15 42 a0 26 ae c9 0e 43 a1 92 c3 95 47 03 17
#   e6 c2 1f 54 39 f7 ca fa cb 32 ce 38 e3 02 b3 2c
#   ac 54 66 58 23 69 ae 72 f4 c6 71 43 ca b4 7a 0f
#   5b 20 36 17 cc 21 0c ac 1b 2b 3d 7b 03 09 aa 77
#   5e 1c bd 97 18 02 d4 f2 ed b4 14 5d 9a 3e 77 cd
#   a4 ba a8 3c a3 00 a6 cd ed bc 67 c3 aa 84 4c bc
#   15 e8 77 56 c9 68 de 4a 3c 43 04 3b 7c 7f 35 25
#   89 a1 8f ca b4 e5 69 e7 92 42 44 ce e8 e0 4e 35
#   cf 67 1b 08 82 29 60 c3 65 9f 07 49 32 2d f7 e7
#   a5 c6 e1 40 ab 41 f4 52 0d 1b 70 78 52 47 a5 c3
#   6e 39 64 9a 86 d9 b5 60 0e 0b 18 2e b8 9c 96 91
#   1a 68 11 58 70 04 2a d5 c8 b0 11 0c 00 3c a2 5c
# base_addr:                   0x10000
# headers_size:                0xcc8
# image_size:                  0x3a47a0
# image_header_size:           0x178
# timestamp:                   0x3bc779c7
# certificate_addr:            0x10178
# section_count:               0x18
# section_headers_addr:        0x10348
# init_flags:                  0x5
# entry_addr:                  0xa8fd0b62
# tls_addr:                    0x1d6a80
# pe_stack_commit:             0x80000
# pe_heap_reserve:             0x100000
# pe_heap_commit:              0x1000
# pe_base_addr:                0x10a00
# pe_image_size:               0x3b8100
# pe_checksum:                 0x0
# pe_timestamp:                0x3bc779c7
# debug_pathname_addr:         0x109f4
# debug_filename_addr:         0x10a0a
# debug_unicode_filename_addr: 0x109e0
# kern_thunk_addr:             0x5b702696
# import_dir_addr:             0x0
# lib_versions_count:          0x8
# lib_versions_addr:           0x10960
# kern_lib_version_addr:       0x109c0
# xapi_lib_version_addr:       0x10960
# logo_addr:                   0x10a14
# logo_size:                   0x2b2

# List library versions
pprint(xbe.libraries)
# {'D3D8': <XbeLibrary "D3D8" (1.0.3925)>,
#  'D3DX8': <XbeLibrary "D3DX8" (1.0.3911)>,
#  'DSOUND': <XbeLibrary "DSOUND" (1.0.3936)>,
#  'DSOUNDH': <XbeLibrary "DSOUNDH" (1.0.3937)>,
#  'LIBC': <XbeLibrary "LIBC" (1.0.3911)>,
#  'XAPILIB': <XbeLibrary "XAPILIB" (1.0.3911)>,
#  'XBOXKRNL': <XbeLibrary "XBOXKRNL" (1.0.3911)>,
#  'XNETS': <XbeLibrary "XNETS" (1.0.3911)>}

# List sections
pprint(xbe.sections)
# {'$$XSIMAGE': <XbeSection name='$$XSIMAGE' vaddr=0x3b37a0 vsize=0x1000>,
#  '$$XTIMAGE': <XbeSection name='$$XTIMAGE' vaddr=0x3b0fa0 vsize=0x2800>,
#  '.data': <XbeSection name='.data' vaddr=0x1f1260 vsize=0x1b4d28>,
#  '.rdata': <XbeSection name='.rdata' vaddr=0x1d6620 vsize=0x1ac30>,
#  '.text': <XbeSection name='.text' vaddr=0x11000 vsize=0x16fe40>,
#  'BINK': <XbeSection name='BINK' vaddr=0x1b6c80 vsize=0x114f0>,
#  'BINK16': <XbeSection name='BINK16' vaddr=0x1ca980 vsize=0x131c>,
#  'BINK16M': <XbeSection name='BINK16M' vaddr=0x1cea20 vsize=0x1f8>,
#  'BINK16MX': <XbeSection name='BINK16MX' vaddr=0x1ce380 vsize=0x130>,
#  'BINK16X2': <XbeSection name='BINK16X2' vaddr=0x1ce4c0 vsize=0x558>,
#  'BINK32': <XbeSection name='BINK32' vaddr=0x1c8180 vsize=0x1265>,
#  'BINK32A': <XbeSection name='BINK32A' vaddr=0x1c9400 vsize=0x1579>,
#  'BINK32M': <XbeSection name='BINK32M' vaddr=0x1cf380 vsize=0x14c>,
#  'BINK32MX': <XbeSection name='BINK32MX' vaddr=0x1cec20 vsize=0x1bc>,
#  'BINK32X2': <XbeSection name='BINK32X2' vaddr=0x1cede0 vsize=0x58c>,
#  'BINK4444': <XbeSection name='BINK4444' vaddr=0x1cbca0 vsize=0x15a0>,
#  'BINK5551': <XbeSection name='BINK5551' vaddr=0x1cd240 vsize=0x1134>,
#  'BINKDATA': <XbeSection name='BINKDATA' vaddr=0x3acd40 vsize=0x4250>,
#  'D3D': <XbeSection name='D3D' vaddr=0x180e40 vsize=0x11774>,
#  'D3DX': <XbeSection name='D3DX' vaddr=0x1925c0 vsize=0x6bc>,
#  'DOLBY': <XbeSection name='DOLBY' vaddr=0x3a5fa0 vsize=0x6d98>,
#  'DSOUND': <XbeSection name='DSOUND' vaddr=0x192c80 vsize=0x1c758>,
#  'XNET': <XbeSection name='XNET' vaddr=0x1af3e0 vsize=0x78a0>,
#  'XPP': <XbeSection name='XPP' vaddr=0x1cf4e0 vsize=0x7128>}

# Get detailed section info
xbe.sections['.text'].header
# flags:                           0x16
# virtual_addr:                    0x11000
# virtual_size:                    0x16fe40
# raw_addr:                        0x1000
# raw_size:                        0x16fe40
# section_name_addr:               0x108ae
# section_name_ref_count:          0x0
# head_shared_page_ref_count_addr: 0x10888
# tail_shared_page_ref_count_addr: 0x1088a
# digest:
#   ef 4b 7f d1 b2 a5 b1 66 c6 d0 22 70 f4 92 00 cc
#   98 5e 7e 6a

# Get section data
len(xbe.sections['.text'].data)
# 1506880
```

Thanks
------
Information about the XBE format derived from [caustik's
work](http://www.caustik.com/cxbx/download/xbe.htm).

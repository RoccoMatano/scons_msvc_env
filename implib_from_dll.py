################################################################################
#
# Copyright 2016-2021 Rocco Matano
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
################################################################################

import sys
import os
import re
import struct
import pathlib
import collections

################################################################################
#
# Creating an import library from an existing DLL would be straightforward if
# there wasn't that weird platform called 'x86'. When ignoring 'x86' the process
# would simply be:
#  - call 'dumpbin /exports <dll name>'
#  - put the output of dumpbin into a '.def' file
#  - call 'lib /def:<.def file>'
#
# On platforms other than 'x86' getting the import library is almost as simple
# as that: You have to filter some data from the output of dumpbin, but that is
# all you have to do.
#
# On 'x86' there are those annoying name decorations, which make things more
# complicated:
#  - To be able to attain the required decorated names, symbol information (pdb)
#    for the DLL in question has to be available.
#  - When creating the .def file, the output of dumpbin has to be transformed,
#    so that the .def file contains the exported names in the correct decoration.
#  - Even if the .def file contains the correct decorations, the lib tool will
#    not mark the entries in the .lib file with the correct decoration flags.
#    That has to be done manually in a post processing step.
#
################################################################################

# format:
#    <ordinal> <hint> <rva> <external name> [ = <internal name>]
# or
#    <ordinal> <hint>       <external name> (<forward info>)
rx_exp86 = re.compile(
    r"""
    \s+                     # space
    \d+                     # decimal ordinal
    \s+                     # space
    [0-9A-Fa-f]+            # hexadecimal hint
    \s+                     # space
    [0-9A-Fa-f]+            # hexadecimal rva
    \s+                     # space
    (\S+)                   # external name
    \s+=\s+                 # equal sign
    (\S+)                   # internal name
    """,
    re.VERBOSE
    )
rx_exp64 = re.compile(
    r"""
    \s+                     # space
    \d+                     # decimal ordinal
    \s+                     # space
    [0-9A-Fa-f]+            # hexadecimal hint
    \s+                     # space
    (?:[0-9A-Fa-f]+){0,1}   # optional hexadecimal rva
    \s+                     # space
    (\S+)                   # external name
    """,
    re.VERBOSE
    )
rx_stdcall86 = re.compile(r"^_[_a-zA-Z][_a-zA-Z0-9]+(@\d+)$")
rx_fastcall = re.compile(r"^@[_a-zA-Z][_a-zA-Z0-9]+(@\d+)$")

################################################################################

IMAGE_DOS_SIGNATURE = 0x5A4D      # MZ
IMAGE_NT_SIGNATURE = 0x00004550   # PE00
IMAGE_FILE_MACHINE_UNKNOWN = 0
IMAGE_FILE_MACHINE_I386 = 0x014c
fmt_IMAGE_DOS_HEADER = "30HL"
size_IMAGE_DOS_HEADER = struct.calcsize(fmt_IMAGE_DOS_HEADER)

fmt_IMAGE_FILE_HEADER_Machine = "LH"
size_IMAGE_FILE_HEADER_Machine = struct.calcsize(fmt_IMAGE_FILE_HEADER_Machine)

################################################################################

def is_x86_binary(filename):
    not_executable = ValueError("not an executable")
    with open(filename, "rb") as f:
        dta = f.read(size_IMAGE_DOS_HEADER)
        if len(dta) < size_IMAGE_DOS_HEADER:
            raise not_executable
        t = struct.unpack(fmt_IMAGE_DOS_HEADER, dta)
        if t[0] != IMAGE_DOS_SIGNATURE:
            raise not_executable
        e_lfanew = t[-1]
        f.seek(e_lfanew)

        dta = f.read(size_IMAGE_FILE_HEADER_Machine)
        if len(dta) < size_IMAGE_FILE_HEADER_Machine:
            raise not_executable
        signature, machine = struct.unpack(fmt_IMAGE_FILE_HEADER_Machine, dta)
        if signature != IMAGE_NT_SIGNATURE:
            raise not_executable
        return machine == IMAGE_FILE_MACHINE_I386

################################################################################

class namedstruct:
    """Helper class for serialising and  deserialising C structs"""

    def __init__(self, name, *args, **kwargs):
        field_formats = [kwargs.get("endianness", "")]
        field_names = []
        for field_name, field_fmt in args:
            field_names.append(field_name)
            field_formats.append(field_fmt)
        self._fmt = "".join(field_formats)
        self._size = struct.calcsize(self._fmt)
        expected = kwargs.get("expected_size", -1)
        if expected >= 0 and expected != self._size:
            raise RuntimeError(
                f"actual size ({self._size}) != expected ({expected})"
                )
        self._nt = collections.namedtuple(name, field_names)

    def __call__(self, *args):
        return self._nt(*args)

    def pack(self, *args):
        if len(args) != 1 or not isinstance(args[0], self._nt):
            return struct.pack(self._fmt, *args)
        return struct.pack(self._fmt, *args[0])

    def unpack(self, data):
        t = self._nt(*struct.unpack(self._fmt, data))
        return t[0] if len(t) == 1 else t

    def unpack_from(self, data, offset=0):
        t = self._nt(*struct.unpack_from(self._fmt, data, offset))
        return t[0] if len(t) == 1 else t

    def size(self):
        return self._size

################################################################################

IAMH_t = namedstruct(
    "IMAGE_ARCHIVE_MEMBER_HEADER",
    ("Name",      "16s"),
    ("Date",      "12s"),
    ("UserID",    "6s"),
    ("GroupID",   "6s"),
    ("Mode",      "8s"),
    ("Size",      "10s"),
    ("EndHeader", "2s"),
    endianness="<",
    expected_size=60
    )

################################################################################

IMAGE_ARCHIVE_START = b"!<arch>\n"
IMAGE_ARCHIVE_END   = b"`\n"
IMPORT_OBJECT_HDR_SIG2 = 0xffff

### IMPORT_OBJECT_TYPE ###
IMPORT_OBJECT_CODE = 0
IMPORT_OBJECT_DATA = 1
IMPORT_OBJECT_CONST = 2

### IMPORT_OBJECT_NAME_TYPE ###
# Import by ordinal
IMPORT_OBJECT_ORDINAL = 0
# Import name == public symbol name.
IMPORT_OBJECT_NAME = 1
# Import name == public symbol name skipping leading ?, @, or optionally _
IMPORT_OBJECT_NAME_NO_PREFIX = 2
# Import name == public symbol name skipping leading ?, @, or optionally _
# and truncating at first @
IMPORT_OBJECT_NAME_UNDECORATE = 3
# Import name == a name is explicitly provided after the DLL name.
IMPORT_OBJECT_NAME_EXPORTAS = 4

################################################################################

IOH_t = namedstruct(
    "IMPORT_OBJECT_HEADER",
    ("Sig1",          "H"), # Must be IMAGE_FILE_MACHINE_UNKNOWN
    ("Sig2",          "H"), # Must be IMPORT_OBJECT_HDR_SIG2
    ("Version",       "H"),
    ("Machine",       "H"),
    ("TimeDateStamp", "I"),
    ("SizeOfData",    "I"),
    ("OrdinalOrHint", "H"),
    ("TypeNameRes",   "H"),
    endianness="<",
    expected_size=20
    )

IOH_TypeMask = 0x3
IOH_TypeShift = 0
IOH_NameMask = 0x1c
IOH_NameShift = 2

################################################################################

def fix_x86_decorations_in_lib(lib_name):
    with open(lib_name, "rb") as f:
        data = bytearray(f.read())

    if data[:len(IMAGE_ARCHIVE_START)] != IMAGE_ARCHIVE_START:
        raise ValueError(f"not a library: {lib_name}")

    offs = len(IMAGE_ARCHIVE_START)
    while offs < len(data):

        ahdr = IAMH_t.unpack_from(data, offs)
        obj_size = int(ahdr.Size)

        if obj_size < IOH_t.size():
            raise ValueError("corrupt library: obj_size < IOH_t.size()")

        ooffs = offs + IAMH_t.size()
        ohdr = IOH_t.unpack_from(data, ooffs)

        have_to_patch = (
            ohdr.Sig1 == IMAGE_FILE_MACHINE_UNKNOWN and
            ohdr.Sig2 == IMPORT_OBJECT_HDR_SIG2 and
            ohdr.Machine == IMAGE_FILE_MACHINE_I386
            )
        if have_to_patch:
            tnr = (
                (ohdr.TypeNameRes & ~IOH_NameMask) |
                (IMPORT_OBJECT_NAME_UNDECORATE << IOH_NameShift)
                )
            new_ohdr = IOH_t(*(ohdr[:-1] + (tnr,)))
            data[ooffs : ooffs + IOH_t.size()] = IOH_t.pack(new_ohdr)

        thisMemberSize = obj_size + IAMH_t.size()
        thisMemberSize = (thisMemberSize + 1) & ~1  # round up
        offs += thisMemberSize

    with open(lib_name, "wb") as f:
        f.write(data)

################################################################################

def decorate_x86_export(undec, dec):
    # stdcall
    m = rx_stdcall86.match(dec)
    if m:
        return undec + m.group(1)

    # fastcall
    m = rx_fastcall.match(dec)
    if m:
        return "@" + undec + m.group(1)

    # anything else is left unchanged
    return undec

################################################################################

def get_exports(filename, tools):
    out = tools.dumpbin_to_str(["/exports", str(filename)])
    if not tools.arch.is_x86():
        return rx_exp64.findall(out)
    else:
        # need to handle those weird decorations
        # N.B. : dumpbin depends on symbol information to be able to supply
        #        the exports in the form <ext. name> = <int. name> (i.e. it
        #        needs to have symsrv.dll available and _NT_SYMBOL_PATH being
        #        set). Should symbol information not be available it will only
        #        output the external name, keeping rx_exp86 from matching.

        return [
            decorate_x86_export(m.group(1), m.group(2))
            for m in rx_exp86.finditer(out)
            ]

################################################################################

def def_from_dll(def_name, dll_name, tools):
    exports = get_exports(dll_name, tools)
    with open(def_name, "wt") as d:
        d.write(f"LIBRARY {pathlib.Path(dll_name).stem}\nEXPORTS\n")
        for e in exports:
            d.write(f"    {e}\n")
        d.write("\n")

################################################################################

def lib_from_dll(lib_name, dll_name, tools):
    def_name = pathlib.Path(lib_name).with_suffix(".def")
    def_from_dll(def_name, dll_name, tools)
    args = [
        "/nologo",
        "/ignore:4102", # export of deleting destructor
        f"/machine:{tools.arch.value}",
        f"/def:{def_name}",
        f"/out:{lib_name}"
        ]
    tools.lib(args)
    if tools.arch.is_x86():
        fix_x86_decorations_in_lib(lib_name)

################################################################################

def lib_from_system_dll(lib_path, dll_name, tools, prefix=""):
    windir = pathlib.Path(os.environ["windir"])
    dll = windir / "system32" / dll_name
    if tools.arch.is_x86():
        env_arch = os.environ["PROCESSOR_ARCHITECTURE"].lower()
        wow = os.environ.get("PROCESSOR_ARCHITEW6432", "")
        if env_arch != "x86" or wow:
            dll = windir / "syswow64" / dll_name
    dll_lib = lib_path / (prefix + dll.with_suffix(".lib").name)
    lib_from_dll(dll_lib, dll, tools)
    return dll_lib

################################################################################

if __name__ == "__main__":

    from .tools import Tools, Arch

    dll_name = pathlib.Path(sys.argv[1])
    if len(sys.argv) > 2:
        lib_name = pathlib.Path(sys.argv[2])
    else:
        lib_name = dll_name.parent / (dll_name.stem + ".lib")
    arch = Arch.X86 if is_x86_binary(dll_name) else Arch.X64
    lib_from_dll(lib_name, dll_name, Tools(arch=arch))

################################################################################

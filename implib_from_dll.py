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
import ctypes
import pathlib

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

class SerializableStruct(ctypes.Structure):
    "Extending ctypes.Structure for easy serialising and deserialising"

    ############################################################################

    def from_bytes(self, src):
        ctypes.memmove(ctypes.byref(self), bytes(src), ctypes.sizeof(self))

    ############################################################################

    def __init__(self, *args, **kwargs):
        if not kwargs:
            # init fields from positional arguments
            super().__init__(*args)
        elif args:
            raise RuntimeError("use either positional or named arguments")
        else:
            # init structure from serialized byte stream
            buffer = kwargs.get("buffer")
            offset = kwargs.get("offset", 0)
            self.from_bytes(buffer[offset:offset + ctypes.sizeof(self)])

    ############################################################################

    def __repr__(self):
        fields = getattr(self, '_fields_', None)
        if fields:
            items = (f"{f[0]}={getattr(self, f[0])!r}" for f in fields)
            return f"{type(self).__name__}({', '.join(items)})"
        return super().__repr__()

################################################################################

IMAGE_DOS_SIGNATURE = 0x5A4D      # MZ
IMAGE_NT_SIGNATURE = 0x00004550   # PE00
IMAGE_FILE_MACHINE_UNKNOWN = 0
IMAGE_FILE_MACHINE_I386 = 0x014c

class IMAGE_DOS_HEADER(SerializableStruct):
    _fields_ = (
        ("signature", ctypes.c_ushort),
        ("dummy", ctypes.c_ushort * 29),
        ("e_lfanew", ctypes.c_ulong)
        )

class IMAGE_FILE_HEADER_Machine(SerializableStruct):
    _fields_ = (("signature", ctypes.c_ulong), ("machine", ctypes.c_ushort))

################################################################################

def is_x86_binary(filename):
    not_executable = ValueError("not an executable")
    with open(filename, "rb") as f:
        size_IDH = ctypes.sizeof(IMAGE_DOS_HEADER)
        dta = f.read(size_IDH)
        if len(dta) < size_IDH:
            raise not_executable
        idh = IMAGE_DOS_HEADER(buffer=dta)
        print(idh, idh.signature, idh.e_lfanew)
        if idh.signature != IMAGE_DOS_SIGNATURE:
            raise not_executable
        f.seek(idh.e_lfanew)

        size_IFHM = ctypes.sizeof(IMAGE_FILE_HEADER_Machine)
        dta = f.read(size_IFHM)
        if len(dta) < size_IFHM:
            raise not_executable
        ifhm = IMAGE_FILE_HEADER_Machine(buffer=dta)
        print(ifhm, ifhm.signature, ifhm.machine)
        if ifhm.signature != IMAGE_NT_SIGNATURE:
            raise not_executable
        return ifhm.machine == IMAGE_FILE_MACHINE_I386

################################################################################

class IMAGE_ARCHIVE_MEMBER_HEADER(SerializableStruct):
    _fields_ = (
        ("Name",      ctypes.c_char * 16),
        ("Date",      ctypes.c_char * 12),
        ("UserID",    ctypes.c_char * 6),
        ("GroupID",   ctypes.c_char * 6),
        ("Mode",      ctypes.c_char * 8),
        ("Size",      ctypes.c_char * 10),
        ("EndHeader", ctypes.c_char * 2),
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

class IMPORT_OBJECT_HEADER(SerializableStruct):
    _fields_ = (
        ("Sig1",          ctypes.c_ushort), # Must be IMAGE_FILE_MACHINE_UNKNOWN
        ("Sig2",          ctypes.c_ushort), # Must be IMPORT_OBJECT_HDR_SIG2
        ("Version",       ctypes.c_ushort),
        ("Machine",       ctypes.c_ushort),
        ("TimeDateStamp", ctypes.c_ulong),
        ("SizeOfData",    ctypes.c_ulong),
        ("OrdinalOrHint", ctypes.c_ushort),
        ("TypeNameRes",   ctypes.c_ushort),
        )

IOH_TYPEMASK = 0x3
IOH_TYPESHIFT = 0
IOH_NAMEMASK = 0x1c
IOH_NAMESHIFT = 2

################################################################################

def fix_x86_decorations_in_lib(lib_name):
    with open(lib_name, "rb") as f:
        data = bytearray(f.read())

    lias = len(IMAGE_ARCHIVE_START)
    lioh = ctypes.sizeof(IMPORT_OBJECT_HEADER)

    if data[:lias] != IMAGE_ARCHIVE_START:
        raise ValueError(f"not a library: {lib_name}")

    namtyp = IMPORT_OBJECT_NAME_UNDECORATE << IOH_NAMESHIFT
    ohdr = IMPORT_OBJECT_HEADER()
    offs = lias
    while offs < len(data):

        ahdr = IMAGE_ARCHIVE_MEMBER_HEADER(buffer=data, offset=offs)
        obj_size = int(ahdr.Size)

        if obj_size < lioh:
            raise ValueError("corrupt library: obj_size < IMPORT_OBJECT_HEADER")

        ooffs = offs + ctypes.sizeof(ahdr)
        ohdr.from_bytes(data[ooffs:])

        have_to_patch = (
            ohdr.Sig1 == IMAGE_FILE_MACHINE_UNKNOWN and
            ohdr.Sig2 == IMPORT_OBJECT_HDR_SIG2 and
            ohdr.Machine == IMAGE_FILE_MACHINE_I386
            )
        if have_to_patch:
            ohdr.TypeNameRes = (ohdr.TypeNameRes & ~IOH_NAMEMASK) | namtyp
            data[ooffs : ooffs + lioh] = bytes(ohdr)

        thisMemberSize = obj_size + ctypes.sizeof(ahdr)
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

        result = [
            decorate_x86_export(m.group(1), m.group(2))
            for m in rx_exp86.finditer(out)
            ]
        if not result:
            raise ValueError("didn't find any x86 exports (no symbols?)")
        return result

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

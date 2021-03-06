################################################################################
#
# Copyright 2020-2022 Rocco Matano
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

"""
The aim of this module is to provide a way to use Visual C++ instances that have
been 'copy deployed'. This file contains the code to choose one of the installed
versions. The information about which versions are available, where they can be
found and how to setup environment variables is kept in an external script.
The path to that script is either taken from the environment variable
'SET_VC_PATH' or it's simply the hardcoded name 'setvc'. That script takes two
parameters: The first one is the MSVS version number (e.g. 16 for Visual Studio
2019) and the second one is the target architechture (e.g. 'x64').
"""

import os
import enum
import time
import json
import logging
import pathlib
import subprocess

################################################################################

class Ver(enum.IntEnum):
    VC9  =  9   # Visual Studio 2008, _MSC_VER 1500, MSVC  9.0
    VC11 = 11   # Visual Studio 2012, _MSC_VER 1700, MSVC 11.0
    VC14 = 14   # Visual Studio 2015, _MSC_VER 1900, MSVC 14.0
    VC15 = 15   # Visual Studio 2017, _MSC_VER 1910, MSVC 14.1
    VC16 = 16   # Visual Studio 2019, _MSC_VER 1920, MSVC 14.2
    VC17 = 17   # Visual Studio 2022, _MSC_VER 1930, MSVC 14.3

    def scons_ver(self):
        lut = {
            # HACK!: Old msvc versions did not require that the pch object was
            #        was given to the linker as an input, but newer version
            #        need this (else error LNK2011). SCons thinks that version
            #        11.0 is the first that requres this, but that is WRONG!
            #        Version 9.0 already needs it. So we tell SCons that it
            #        should handle 9.0 like 11.0.
             9: "11.0",
            11: "11.0",
            14: "14.0",
            15: "14.1",
            16: "14.2",
            17: "14.3",
            }
        return lut[self.value]

################################################################################

class Arch(enum.Enum):
    X86   = "x86"
    I386  = "x86"
    X64   = "x64"
    AMD64 = "x64"

    def is_x86(self):
        return self.value == self.X86.value

    def is_x64(self):
        return self.value == self.X64.value

    def scons_arch(self):
        return "x86" if self.value == self.X86.value else "amd64"

################################################################################

DEFAULT_VER  = Ver.VC17
DEFAULT_ARCH = Arch.X64

################################################################################

_init_env = os.environ.copy()

def _setup_tool_env(ver, arch):
    #
    # Here we call a batch file called 'setvc' that sets the required
    # environment variables (esp. PATH, INCLUDE and LIB), so that it is
    # possible to use the tools according to 'ver' and 'arch'.
    # But those variables are set in a seperate shell process. In order
    # to get hold of the environ of that shell, we not only execute
    # the batch file, but we also let the shell output its environment
    # to stdout (via '&& set'). Then we parse that output.

    start = time.perf_counter()

    setvc = os.environ.get("SET_VC_PATH", "setvc")

    args = [setvc, str(ver), str(arch), "&&", "set"]
    logging.info(f"COMMAND\n{subprocess.list2cmdline(args)}\n")
    # Use _init_env so that this function can be called repeatedly even
    # if the extracted env will become part of the env of this process.
    out = subprocess.run(
        args,
        env=_init_env,
        shell=True, # use shell for PATH and extension handling
        text=True,
        check=True,
        stdout=subprocess.PIPE
        ).stdout
    env = {}
    keep = (
        "INCLUDE",
        "LIB",
        "PATH",
        "VCINSTALLDIR",
        "_NT_SYMBOL_PATH",  # need _NT_SYMBOL_PATH for ImpLibFromSystemDll
        )
    for line in reversed(out.splitlines()):
        idx = line.find("=")
        if idx < 0:
            break
        name = line[:idx].upper()
        if name in keep:
            value = line[idx + 1:]
            logging.info(f"{name}={value}")
            env[name] = value
    logging.info(f"time for mvsc environment: {time.perf_counter() - start}s")
    return env

################################################################################

ENV_CACHE_FILE = pathlib.Path(__file__).parent.resolve() / "msvc_env_cache.json"
_env_cache = {}

try:
    with open(ENV_CACHE_FILE, "r") as jfile:
        _env_cache = json.load(jfile)
except OSError:
    pass

################################################################################

def get_msvc_env(ver, arch, ignore_cache):
    if ignore_cache:
        return _setup_tool_env(ver.value, arch.value)
    global _env_cache
    key = f"vc{ver.value}_{arch.value}"
    if not key in _env_cache:
        _env_cache[key] = _setup_tool_env(ver.value, arch.value)
        try:
            with open(ENV_CACHE_FILE, "w") as jfile:
                json.dump(_env_cache, jfile, indent=4)
        except OSError:
            pass
    return _env_cache[key]


def reset_env_cache():
    global _env_cache
    _env_cache = {}

################################################################################

class ToolChain:
    def __init__(self, *args):
        if len(args) == 3:
            ver, self.arch, ignore_cache = args
            self.env = get_msvc_env(ver, self.arch, ignore_cache)
        elif len(args) == 2:
            self.arch, self.env = args
        else:
            raise TypeError("invalid number of arguments")

    @classmethod
    def default(cls, arch=DEFAULT_ARCH):
        return cls(DEFAULT_VER, arch, False)

    def _run(self, args, catch_output=False):
        logging.info(f"COMMAND: {subprocess.list2cmdline(args)}")
        kwargs = {"check": True, "shell": True, "env": self.env}
        if catch_output:
            kwargs["stdout"] = subprocess.PIPE
        proc = subprocess.run(args, **kwargs)
        if catch_output:
            return proc.stdout.decode("ascii", errors="backslashreplace")

    def lib(self, args):
        res_args = ["lib"]
        res_args.extend(map(str, args))
        self._run(res_args)

    def dumpbin(self, args, as_str=True):
        res_args = ["dumpbin"]
        res_args.extend(map(str, args))
        return self._run(res_args, as_str)

################################################################################

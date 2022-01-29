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
While I like the way SCons allows to *use* MSVC, I completely dislike the way
how SCons can be configured regarding the version of MSVC it is going to use.
I prefer to make that decision on a per project basis *and* being able to
choose from several versions that are installed in a 'copy deployment' fashion
(i.e. cannot be found by SCons). The code to choose one of the installed
versions and to setup SCons environments for those can be found in module
'msvc_tools'.

Additional features compared to standard SCons:
 - support for assembler listings
 - support for map files
 - a builder that removes the PCH symbol from object files
 - a builder that creates an import lib for a system dll (e.g. msvcrt.dll)
 - a builder that pre-processes C/C++ files
"""

################################################################################

import os
import re
import copy
import atexit
import logging
import pathlib
import subprocess
import dataclasses
import msvc_tools
from msvc_tools import Ver, Arch, DEFAULT_VER, DEFAULT_ARCH
import implib_from_dll
import SCons
# While SCons.Script has a sub-module called 'SConscript' it also defines an
# attribute of the same name. So we have to use 'SConscript' in an import
# statement to get hold of the sub-module.
from SCons.Script.SConscript import SConsEnvironment
import SCons.Defaults

################################################################################

# We are going to inhibit the detection of MSVC during the creation of our
# MSVC env (see MSVC_SETUP_RUN below). But on Windows SCons still thinks, MSVC
# should be part of the default env. When the default env singleton is created
# this costs unnecessary time for MSVC detection and can trigger SCons warnings
# if MSVC is not found. Therefore we are now explicitly creating the default
# env singleton without requesting the MSVC tools. More precisely: requesting no
# tools at all (tools=[]). Of course this only works, if the default env has not
# yet been created by someone else.

SCons.Defaults.DefaultEnvironment(tools=[])

################################################################################

globals().update(Ver.__members__)
globals().update(Arch.__members__)

THIS_DIR = pathlib.Path(__file__).parent.resolve()

################################################################################

@dataclasses.dataclass
class BuildCfg:
    subsystem: str = "windows"
    entry: str = "entry_point"
    stub: str = str(THIS_DIR / "roma.stub")
    parse_opt: bool = True
    ver: Ver = DEFAULT_VER
    arch: Arch = DEFAULT_ARCH
    noasm: bool = False
    nomap: bool = False
    pdb: bool = False
    nop: bool = False
    verbose: bool = False
    prefix: str = ""
    defines: dict = dataclasses.field(default_factory=dict)
    nocache: bool = False
    noltcg: bool = False

    def copy(self):
        # since 'defines' is a container, we have to do a deep copy
        return copy.deepcopy(self)

################################################################################

# options can only be added once
_options_have_been_added = False

def _parse_options(cfg):
    if cfg.parse_opt:
        global _options_have_been_added
        if not _options_have_been_added:
            _options_have_been_added = True
            verset = set(v.value for v in Ver.__members__.values())
            archset = set(v.value for v in Arch.__members__.values())
            AddOption = SCons.Script.AddOption
            AddOption("--vc", help=f"vc ver {verset}")
            AddOption("--arch", help=f"target arch {archset}")
            AddOption("--def", help="cpp defines: n1[=v1][$n2[=v2]]")
            AddOption("--nop", action="store_true", help="no optimization")
            AddOption("--pdb", action="store_true", help="create PDB")
            AddOption("--nomap", action="store_true", help="no map file")
            AddOption("--noasm", action="store_true", help="no asm listings")
            AddOption("--verbose", action="store_true", help="be verbose")
            AddOption("--prefix", help="build path pefix")
            AddOption(
                "--nocache",
                action="store_true",
                help="ignore cached msvc environments"
                )
            AddOption(
                "--noltcg",
                action="store_true",
                help="no link time code generation"
                )

        GetOption = SCons.Script.GetOption
        ver = GetOption("vc")
        if ver:
            cfg.ver = Ver(float(ver))
        arch = GetOption("arch")
        if arch:
            cfg.arch = Arch[arch.upper()]
        defines = GetOption("def")
        if defines:
            for d in defines.split("$"):
                nv = d.split("=")
                name, value = nv if len(nv) > 1 else (nv[0], None)
                cfg.defines[name] = value
        if GetOption("nop"):
            cfg.nop = cfg.pdb = True
        if GetOption("pdb"):
            cfg.pdb = True
        if GetOption("nomap"):
            cfg.nomap = True
        if GetOption("noasm"):
            cfg.noasm = True
        if GetOption("nocache"):
            cfg.nocache = True
        if GetOption("noltcg"):
            cfg.noltcg = True
        if GetOption("verbose"):
            cfg.verbose = True
            logging.basicConfig(level=logging.DEBUG)
            logging.info(f"\n\nactivated logging\n\n")

        prefix = GetOption("prefix")
        if prefix:
            cfg.prefix = prefix

################################################################################

class MsvcEnvironment(SConsEnvironment):

    def __init__(self, cfg=BuildCfg(), **kw):
        # ensure to request msvc tools
        tools = kw.get("tools", [])
        for tool in ("msvc", "mslib", "mslink"):
            if tool not in tools:
                tools.append(tool)
        kw["tools"] = tools

        # do not overwrite attributes in cfg by making a copy
        self.cfg = cfg.copy()
        # potentially overwrite cfg with values from command line
        _parse_options(self.cfg)

        # let SCons know which version we are going to use and init SCons'
        # MSVC support while inhibiting detection of MVSC
        kw["MSVC_SETUP_RUN"] = True # this inhibts the detection
        kw["MSVC_VERSION"] = kw["MSVS_VERSION"] = self.cfg.ver.scons_ver()
        kw["TARGET_ARCH"] = self.cfg.arch.scons_arch()
        super().__init__(**kw)

        # since we have inhibited the standard detection, we have to catch up
        # on setting 'ENV'.
        vcenv = msvc_tools.get_msvc_env(
            self.cfg.ver,
            self.cfg.arch,
            self.cfg.nocache
            )
        for k, v in vcenv.items():
            self.PrependENVPath(k, v, delete_existing=True)

        # now we are going to adapt SCons' MSVC support

        # set our preferred flags
        cflags, lflags = (
            self.get_not_optimized_flags() if self.cfg.nop else
            self.get_optimized_flags()
            )
        self.Append(CCFLAGS=cflags)
        self.Append(LINKFLAGS=lflags)
        if cfg.defines:
            self.Append(CPPDEFINES=cfg.defines)

        if not self.cfg.nomap:
            self["MAPFILE"] = True
        if not self.cfg.noasm:
            self["ASMLST"] = True

        # extend '_PDB' to do several things (not just for PDBs)
        # - use /debug:full when available for creating PDBs
        # - use /map when a map file was requested
        self["_PDB"] = self._link_gen

        # extending emitter for map files
        for ename in ("PROGEMITTER", "SHLIBEMITTER"):
            elist = self[ename]
            elist.insert(0, self._pdb_emitter)
            elist.append(self._map_emitter)
            self[ename] = elist

        # add support for assembler listings

        # adding flags
        self._orig_output_gen = self["_MSVC_OUTPUT_FLAG"]
        self["_MSVC_OUTPUT_FLAG"] = self._output_gen
        # extending emitter
        self._builder_append_emitter("Object", self._asm_list_emitter)
        # extra punk for pch
        self["PCHPDBFLAGS"] = self._pch_gen
        self._builder_append_emitter("PCH", self._asm_list_emitter)

        # add a builder that removes the PCH symbol from object files
        Action = SCons.Action.Action
        self["BUILDERS"]["PatchPchSym"] = self.Builder(
            emitter=self._patch_pch_sym_emitter,
            action=Action(self._patch_pch_sym_action, "Patching PCH symbol")
            )

        # add a builder that creates an import library from a system DLL
        self["BUILDERS"]["ImpLibFromSystemDll"] = self.Builder(
            emitter=self._ilfsdll_emitter,
            action=Action(self._ilfsdll_action, "Creating import lib $TARGET")
            )

        # add a builder that preprocesses a source file
        self["BUILDERS"]["PreProcess"] = self.Builder(
            action=Action(self._cpp_action, "Preprocessing $SOURCE"),
            suffix=".i"
            )

        # do not leave running mspdbsrv behind
        atexit.register(self._cleanup)

        # initially no pch
        self.pch = ""

    ############################################################################

    def _cleanup(self):
        kwargs = {
            "check": False,
            "stderr": subprocess.PIPE,
            "env": self["ENV"],
            "shell": True,
            }
        subprocess.run(["mspdbsrv", "-stop"], **kwargs)

    ############################################################################

    def Clone(self, tools=[], toolpath=None, parse_flags=None, **kw):
        clone = super().Clone(tools, toolpath, parse_flags, **kw)
        clone.cfg = self.cfg.copy()
        clone._orig_output_gen = self._orig_output_gen
        clone.pch = self.pch[:]
        return clone

    ############################################################################

    def CloneNoGL(self):
        clone = self.Clone()
        try:
            clone["CCFLAGS"].remove("/GL")
        except ValueError:
            pass
        return clone

    ############################################################################

    def no_gl_object(self, src):
        return self.CloneNoGL().Object(source=src)

    ############################################################################

    def modify_flags(self, name, add, remove=None):
        flags = self[name][:]
        if remove:
            to_be_removed = []
            for r in remove:
                if r in flags:
                    to_be_removed.append(r)
                else:
                    rx = re.compile(r)
                    to_be_removed.extend([f for f in flags if rx.match(f)])
            for r in to_be_removed:
                flags.remove(r)
        if add:
            flags.extend(add)
        self[name] = flags

    ############################################################################

    def use_pch(self, name="pch.h", impl=None, impl_ext=".cpp"):
        self.pch = name
        if impl is None:
            impl = name.rsplit(".", 1)[0] + impl_ext
        self["PCHSTOP"] = name
        self["PCH"] = self.PCH(impl)[0]

    ############################################################################

    def get_pch(self):
        return self.pch

    ############################################################################

    def force_include_pch(self):
        self.modify_flags("CCFLAGS", [f"/FI{self.pch}"])

    ############################################################################

    def get_target_dir(self, parent):
        target = self.cfg.prefix + self.cfg.arch.value
        if self.cfg.nop:
            target += "_nop"
        elif self.cfg.pdb:
            target += "_pdb"
        return self.Dir(target, parent)

    ############################################################################

    def set_build_dir(self, sdir, bdir):
        if isinstance(sdir, str):
            sdir = self.Dir(sdir)
        build_path = self.get_target_dir(bdir)
        self.VariantDir(build_path, sdir, False)
        self.fs.chdir(build_path, False)
        return build_path

    ############################################################################

    def _builder_append_emitter(self, name, add_emitter):
        prev_bld = self["BUILDERS"][name]
        self["BUILDERS"][name] = self.Builder(
            action=prev_bld.action,
            emitter=[prev_bld.emitter, add_emitter],
            suffix=prev_bld.suffix,
            prefix=prev_bld.prefix,
            src_builder=prev_bld.src_builder,
            source_scanner=prev_bld.source_scanner,
            single_source=prev_bld.single_source,
            multi = prev_bld.multi,
            )

    ############################################################################

    def _output_gen(self, target, source, env, for_signature):
        res = self._orig_output_gen(target, source, env, for_signature)
        if self.get("ASMLST", None):
            res += f" /FAs /Fa{target[0].base}.asm"
        return res

    ############################################################################

    def _pch_gen(self, target, source, env, for_signature):
        res = ""
        if self.get("ASMLST", None):
            res += f" /FAs /Fa{target[0].base}.asm"
        return res

    ############################################################################

    def with_suffix(self, entry, suffix):
        # Since entry.suffix might not be a str but a SpecialAttrWrapper, we
        # have to call str() on it.
        suf_len = len(str(entry.suffix))
        return self.File(entry.name[:-suf_len] + suffix, entry.dir)

    ############################################################################

    def _link_gen(self, env, target, source, for_signature):
        flags = []
        if self.cfg.pdb:
            flags.append(f"/pdb:{target[0].attributes.pdb}")
            flags.append("/debug" if self.cfg.ver == VC9 else "/debug:full")
        if self.get("MAPFILE", None):
            flags.append(f"/map:{self.with_suffix(target[0], '.map')}")
        if self.get("ASMLST", None):
            flags.append("/ltcgasmlist")
        return flags or None

    ############################################################################

    def _map_emitter(self, target, source, env):
        if self.get("MAPFILE", None):
            for t in target:
                map = self.with_suffix(target[0], ".map")
                env.SideEffect(map, t)
                env.Clean(t, map)
        return target, source

    ############################################################################

    def _pdb_emitter(self, target, source, env):
        if self.cfg.pdb:
            env["PDB"] = self.with_suffix(target[0], ".pdb").name
        return target, source

    ############################################################################

    def _asm_list_emitter(self, target, source, env):
        if self.get("ASMLST", None):
            for t in target:
                # Here we might get a target of type str (pch). So we cannot
                # call with_suffix here.
                asm = str(t).rsplit(".", 1)[0] + ".asm"
                env.SideEffect(asm, t)
                env.Clean(t, asm)
        return target, source

    ############################################################################

    def _get_common_flags(self):
        ver = self.cfg.ver.value
        verbose = self.cfg.verbose

        cflags = [
            "/W4",
            "/GF",
            "/GS-",
            "/Gy",
            "/MD",
            "/EHs-c-",
            ]
        if ver >= 16:
            cflags.extend(
                ["/permissive-", "/diagnostics:caret", "/Zc:__cplusplus"]
                )
        if verbose:
            cflags.append("/Bd")

        lflags = [
            f"/subsystem:{self.cfg.subsystem}",
            "/nxcompat",
            "/manifest:no",
            ]
        if self.cfg.entry:
            lflags.append(f"/entry:{self.cfg.entry}")
        if self.cfg.stub:
            lflags.append(f"/stub:{self.cfg.stub}")
        if verbose:
            #lflags.extend(["/verbose", "/test"])
            lflags.extend(["/test"])

        return cflags, lflags

    ############################################################################

    def get_optimized_flags(self):
        ver = self.cfg.ver.value
        ltcg = not self.cfg.noltcg

        cflags, lflags = self._get_common_flags()
        cflags.extend(["/O1", "/Os", "/Oy", "/GR-"])
        if ltcg:
            cflags.append("/GL")

        if ver >= 14:
            cflags.append("/Gw")

        ladd = [
            "/incremental:no",
            "/release",
            "/dynamicbase:no",
            "/fixed",
            "/last:.pdata",
            "/opt:ref",
            "/opt:icf",
            ]
        lflags.extend(ladd)
        if ltcg:
            lflags.append("/ltcg")
        if ver >= 14:
            lflags.append("/nocoffgrpinfo")
        # try to optimize use of sections
        if ver <= 11:
            lflags.append("/merge:.rdata=.text")

        return cflags, lflags

    ############################################################################

    def get_not_optimized_flags(self):
        cflags, lflags = self._get_common_flags()
        cflags.extend(["/Od",])
        return cflags, lflags

    ############################################################################

    def adapt_for_dll(self, add_cflags=None, deffile=None):
        add = ["/dll"]
        if deffile:
            add.append(f"/def:{deffile}")
        rem = ["(?i)/fixed", "(?i)/dynamicbase.*"]
        self.modify_flags("LINKFLAGS", add, rem)
        if add_cflags:
            self.Append(CCFLAGS=add_cflags)

    ############################################################################

    def _patch_pch_sym_emitter(self, target, source, env):
        target = [self.with_suffix(s, ".pps" + s.suffix) for s in source]
        return target, source

    ############################################################################

    def _patch_pch_sym_action(self, target, source, env):
        """
        MSVC has a method to ensure that for builds with PCH all objects linked
        together are built using the same PCH. This works by injecting the
        definition of a symbol in the form of '__@@_PchSym_.*' into the PCH
        and injecting a reference to that symbol into all objects that are built
        using the PCH. Unfortunately the linker will not only ensure the
        presence of that symbol, it also places it into the executable :-(

        While this method can be switched off by using '/Yl-', that's only
        possible when no LTCG is active (i.e. no '/GL'). When LTCG is active,
        '/Yl-' will emit a warning and have no further effect.

        So this method iterates over the object files and purges the forced
        references to '__@@_PchSym_.*'.
        Of course, using this method means that it becomes the responsibility
        of the user to take care of the proper use of PCH.
        """
        for src in source:
            data = src.get_contents()
            idx = data.find(b"-INCLUDE:__@@_PchSym_")
            if idx < 0:
                # one more '_' for x86
                idx = data.find(b"-INCLUDE:___@@_PchSym_")
            if idx >= 0:
                arr = bytearray(data)
                while arr[idx] != 0:
                    arr[idx] = ord(" ")
                    idx += 1
                data = arr
            fname = self.with_suffix(src, ".pps" + src.suffix).path
            with open(fname, "wb") as of:
                of.write(data)

    ############################################################################

    def _ilfsdll_emitter(self, target, source, env):
        subdir = "system32"
        if self.cfg.arch.is_x86():
            env_arch = os.environ["PROCESSOR_ARCHITECTURE"].lower()
            wow = os.environ.get("PROCESSOR_ARCHITEW6432", "")
            if env_arch != "x86" or wow:
                subdir = "syswow64"
        sysdir = self.Dir(subdir, os.environ["windir"])
        source[0] = self.File(source[0].name, sysdir)

        for suffix in (".def", ".exp"):
            target.append(self.with_suffix(target[0], suffix))
        return target, source

    ############################################################################

    def _ilfsdll_action(self, target, source, env):
        tools = msvc_tools.ToolChain(self.cfg.arch, self["ENV"])
        implib_from_dll.lib_from_dll(target[0].path, source[0].path, tools)

    ############################################################################

    def _cpp_action(self, target, source, env):
        kwargs = {
            "check": True,
            "env": env["ENV"],
            "shell": True,
            "stdout": subprocess.PIPE,
            "text": True
            }
        plainc = source[0].suffix in (".c", ".C")
        com = env["CCCOM"] if plainc else env["CXXCOM"]
        com = env.subst(com.replace("/c", "/E"), target=target, source=source)
        res = subprocess.run(com, **kwargs).stdout
        with open(str(target[0]), "wt") as pp:
            pp.write(res)

################################################################################

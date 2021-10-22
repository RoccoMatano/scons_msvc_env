import sys
import os
import pathlib

################################################################################

VER = "4.2.0"
SCONS_DIR = f"scons-{VER}/scons-local-{VER}"
BASES = ["c:/prj/progs", "c:/projects"]
SCONS_PROSPECTS = [pathlib.Path(b) / SCONS_DIR for b in BASES]

################################################################################

def prepare_args():
    # replace implicit build script 'SConstruct' with 'sconstruct.py'
    # but only if pure SCons help was not requested
    args = sys.argv[1:]
    if not "-H" in args:
        def build_script_in_args(args):
            for arg in args:
                for prefix in ("-f", "--file", "--makefile", "--sconstruct"):
                    if arg.startswith(prefix):
                        return True
            return False
        if not build_script_in_args(args):
            sys.argv[1:] = ["-f", "sconstruct.py"] + args

################################################################################

def prepare_search_path():
    for prospect in SCONS_PROSPECTS:
        if prospect.exists():
            libs = [str(prospect)]
            break
    else:
        raise EnvironmentError("cannot find SCons directory")
    if "SCONS_LIB_DIR" in os.environ:
        libs.insert(0, os.environ["SCONS_LIB_DIR"])
    sys.path = libs + sys.path

################################################################################

if __name__ == "__main__":

    prepare_args()
    prepare_search_path()

    import SCons.Script
    SCons.Script.main()

################################################################################

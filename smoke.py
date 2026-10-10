"""Native acceptance script embedded unchanged in each target's smoke command."""

import ctypes
import ensurepip
import hashlib
import json
import lzma
import os
from pathlib import Path
import sqlite3
import ssl
import sys
import sysconfig
import tempfile
import venv


assert sys.version_info[:3] == tuple(map(int, "{version}".split(".")))
assert sys.implementation.name == "cpython"
assert "PYTHONHOME" not in os.environ
assert "PYTHONPATH" not in os.environ

application_root = Path(sys.executable).resolve().parent
if sys.platform != "win32":
    application_root = application_root.parent
assert Path(sys.prefix).resolve() == application_root
assert Path(sys.base_prefix).resolve() == application_root
include = Path(sysconfig.get_path("include"))
assert (include / "Python.h").is_file()
if sys.platform == "win32":
    assert (application_root / "libs" / "python37.lib").is_file()
    assert (application_root / "vcruntime140.dll").is_file()
else:
    assert (application_root / "lib" / "libpython3.7m.a").is_file()
assert Path(sysconfig.get_path("stdlib"), "os.py").is_file()
assert Path(sysconfig.get_path("stdlib"), "venv", "__init__.py").is_file()
assert ensurepip.version()
assert ssl.OPENSSL_VERSION
assert hashlib.sha256(b"vx-python-native").hexdigest()
assert lzma.decompress(lzma.compress(b"standalone-runtime")) == b"standalone-runtime"
assert ctypes.sizeof(ctypes.c_void_p) == 8
with sqlite3.connect(":memory:") as database:
    assert database.execute("select 3 + 7").fetchone() == (10,)

with tempfile.TemporaryDirectory(prefix="vx-python-venv-") as temporary:
    environment = Path(temporary) / "environment"
    # Symlink the interpreter rather than copying it. A copy resolves the payload's
    # $ORIGIN-relative libpython against the venv tree, where it is absent, so the
    # venv launcher fails to start even though the payload interpreter is intact.
    venv.EnvBuilder(with_pip=False, symlinks=True).create(str(environment))
    executable = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    assert executable.is_file()
    if sys.platform != "win32":
        assert executable.is_symlink(), "venv copied the interpreter instead of symlinking it"
    import subprocess

    completed = subprocess.run(
        [str(executable), "-I", "-c", "import json,sys;print(json.dumps([list(sys.version_info[:3]),sys.prefix,sys.base_prefix]))"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    version, prefix, base_prefix = json.loads(completed.stdout)
    assert version == [3, 7, 9]
    assert Path(prefix).resolve() == environment.resolve()
    assert Path(base_prefix).resolve() == application_root

print("VX_PYTHON_NATIVE_SMOKE_OK")

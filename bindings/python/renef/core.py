"""
Renef Python Binding
Complete ctypes wrapper for librenef C API
"""

import ctypes
import os
from ctypes import c_char_p, c_int, c_void_p, c_uint8, c_uint16, c_uint32, c_uint64, c_size_t, c_ssize_t, POINTER, Structure, CFUNCTYPE
from typing import Optional, Tuple, List


def _find_library():
    """Find librenef shared library"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.join(script_dir, "..", "..", "..")

    paths = [
        os.path.join(project_root, "build", "librenef.so"),
        os.path.join(project_root, "build", "librenef.so.0"),
        "/usr/local/lib/librenef.so",
    ]

    for path in paths:
        if os.path.exists(path):
            return path
    return None


class RenefResult(Structure):
    _fields_ = [
        ("success", c_int),
        ("output", c_char_p),
        ("error", c_char_p)
    ]


RenefMessageCallback = CFUNCTYPE(None, c_char_p, c_size_t, c_void_p)


class Memory:
    """Memory API wrapper - provides access to target process memory"""

    def __init__(self, session: 'RenefSession'):
        self._session = session

    def read(self, addr: int, size: int) -> Optional[bytes]:
        """Read raw bytes from memory"""
        buf = (c_uint8 * size)()
        n = self._session._lib.renef_read_memory(
            self._session._handle, addr, size, buf
        )
        if n <= 0:
            return None
        return bytes(buf[:n])

    def write(self, addr: int, data: bytes) -> int:
        """Write raw bytes to memory"""
        buf = (c_uint8 * len(data))(*data)
        return self._session._lib.renef_write_memory(
            self._session._handle, addr, buf, len(data)
        )

    def read_u8(self, addr: int) -> int:
        """Read unsigned 8-bit value"""
        return self._session._lib.renef_read_u8(self._session._handle, addr)

    def read_u16(self, addr: int) -> int:
        """Read unsigned 16-bit value"""
        return self._session._lib.renef_read_u16(self._session._handle, addr)

    def read_u32(self, addr: int) -> int:
        """Read unsigned 32-bit value"""
        return self._session._lib.renef_read_u32(self._session._handle, addr)

    def read_u64(self, addr: int) -> int:
        """Read unsigned 64-bit value"""
        return self._session._lib.renef_read_u64(self._session._handle, addr)

    def read_string(self, addr: int, max_len: int = 256) -> Optional[str]:
        """Read null-terminated string"""
        result = self._session._lib.renef_read_string(self._session._handle, addr, max_len)
        output = result.output.decode() if result.output else None
        self._session._lib.renef_result_free(ctypes.byref(result))
        return output

    def write_u8(self, addr: int, val: int) -> int:
        """Write unsigned 8-bit value"""
        return self._session._lib.renef_write_u8(self._session._handle, addr, val)

    def write_u16(self, addr: int, val: int) -> int:
        """Write unsigned 16-bit value"""
        return self._session._lib.renef_write_u16(self._session._handle, addr, val)

    def write_u32(self, addr: int, val: int) -> int:
        """Write unsigned 32-bit value"""
        return self._session._lib.renef_write_u32(self._session._handle, addr, val)

    def write_u64(self, addr: int, val: int) -> int:
        """Write unsigned 64-bit value"""
        return self._session._lib.renef_write_u64(self._session._handle, addr, val)

    def scan(self, pattern: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Scan memory for hex pattern

        Args:
            pattern: Hex pattern (e.g. 'FF 00 ?? 01')

        Returns:
            (success, output, error)
        """
        return self._session.memscan(pattern)


class Module:
    """Module API wrapper - provides access to loaded libraries"""

    def __init__(self, session: 'RenefSession'):
        self._session = session

    def find(self, name: str) -> int:
        """Find module base address by name"""
        return self._session._lib.renef_module_find(self._session._handle, name.encode())

    def list(self) -> List[dict]:
        """
        List all loaded modules

        Returns:
            List of {base: int, name: str}
        """
        result = self._session._lib.renef_module_list(self._session._handle)
        modules = []
        if result.output:
            for line in result.output.decode().strip().split('\n'):
                if line:
                    parts = line.split(' ', 1)
                    if len(parts) == 2:
                        modules.append({
                            'base': int(parts[0], 16),
                            'name': parts[1]
                        })
        self._session._lib.renef_result_free(ctypes.byref(result))
        return modules

    def exports(self, name: str) -> List[dict]:
        """
        Get exported symbols from module

        Returns:
            List of {offset: int, name: str}
        """
        result = self._session._lib.renef_module_exports(self._session._handle, name.encode())
        exports = []
        if result.output:
            for line in result.output.decode().strip().split('\n'):
                if line:
                    parts = line.split(' ', 1)
                    if len(parts) == 2:
                        exports.append({
                            'offset': int(parts[0], 16),
                            'name': parts[1]
                        })
        self._session._lib.renef_result_free(ctypes.byref(result))
        return exports

    def symbols(self, name: str) -> List[dict]:
        """
        Get all symbols from module

        Returns:
            List of {offset: int, name: str}
        """
        result = self._session._lib.renef_module_symbols(self._session._handle, name.encode())
        symbols = []
        if result.output:
            for line in result.output.decode().strip().split('\n'):
                if line:
                    parts = line.split(' ', 1)
                    if len(parts) == 2:
                        symbols.append({
                            'offset': int(parts[0], 16),
                            'name': parts[1]
                        })
        self._session._lib.renef_result_free(ctypes.byref(result))
        return symbols


class Thread:
    """Thread API wrapper"""

    def __init__(self, session: 'RenefSession'):
        self._session = session

    def id(self) -> int:
        """Get current thread ID"""
        return self._session._lib.renef_thread_id(self._session._handle)

    def backtrace(self) -> List[str]:
        """Get stack backtrace"""
        result = self._session._lib.renef_thread_backtrace(self._session._handle)
        frames = []
        if result.output:
            frames = result.output.decode().strip().split('\n')
        self._session._lib.renef_result_free(ctypes.byref(result))
        return frames


class OS:
    """OS API wrapper - process management and filesystem listing via Lua eval"""

    def __init__(self, session: 'RenefSession'):
        self._session = session

    def _eval_int(self, code: str) -> Optional[int]:
        ok, out, _ = self._session.eval(code)
        if ok and out:
            try:
                return int(out.strip())
            except ValueError:
                return None
        return None

    def getpid(self) -> Optional[int]:
        """Get current process ID"""
        return self._eval_int("print(OS.getpid())")

    def kill(self, pid: int, sig: int) -> Optional[int]:
        """Send signal to a process"""
        return self._eval_int(f"print(OS.kill({pid}, {sig}))")

    def tgkill(self, tgid: int, tid: int, sig: int) -> Optional[int]:
        """Send signal to a specific thread"""
        return self._eval_int(f"print(OS.tgkill({tgid}, {tid}, {sig}))")

    def listdir(self, path: str) -> Optional[List[str]]:
        """List directory contents (excludes dotfiles)"""
        code = f"""
local t = OS.listdir("{path}")
if t then
    for i, v in ipairs(t) do print(v) end
else
    print("__NIL__")
end
"""
        ok, out, _ = self._session.eval(code)
        if ok and out:
            out = out.strip()
            if out == "__NIL__":
                return None
            return out.split('\n') if out else []
        return None


class File:
    """File API wrapper - filesystem operations via Lua eval"""

    def __init__(self, session: 'RenefSession'):
        self._session = session

    def read(self, path: str) -> Optional[str]:
        """Read file contents"""
        ok, out, _ = self._session.eval(f"""
local c = File.read("{path}")
if c then print(c) else print("__NIL__") end
""")
        if ok and out:
            out = out.strip()
            return None if out == "__NIL__" else out
        return None

    def exists(self, path: str) -> bool:
        """Check if file exists"""
        ok, out, _ = self._session.eval(f'print(File.exists("{path}"))')
        return ok and out and out.strip() == "true"

    def readlink(self, path: str) -> Optional[str]:
        """Read symlink target"""
        ok, out, _ = self._session.eval(f"""
local t = File.readlink("{path}")
if t then print(t) else print("__NIL__") end
""")
        if ok and out:
            out = out.strip()
            return None if out == "__NIL__" else out
        return None

    def fdpath(self, fd: int) -> Optional[str]:
        """Get path for file descriptor"""
        ok, out, _ = self._session.eval(f"""
local t = File.fdpath({fd})
if t then print(t) else print("__NIL__") end
""")
        if ok and out:
            out = out.strip()
            return None if out == "__NIL__" else out
        return None

    def write(self, path: str, addr: int, size: int) -> bool:
        """Dump memory region to file"""
        ok, out, _ = self._session.eval(f'print(File.write("{path}", {addr}, {size}))')
        return ok and out and out.strip() == "true"


class Syscall:
    """Syscall API wrapper - syscall tracing via Lua eval"""

    def __init__(self, session: 'RenefSession'):
        self._session = session

    def trace(self, *names: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Start tracing syscalls

        Args:
            *names: Syscall names to trace (e.g. "openat", "read", "write")

        Returns:
            (success, output, error)
        """
        args = ', '.join(f'"{n}"' for n in names)
        return self._session.eval(f"Syscall.trace({args})")

    def trace_category(self, category: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Trace all syscalls in a category

        Args:
            category: Category name (e.g. "file", "net", "process")
        """
        return self._session.eval(f'Syscall.trace({{category="{category}"}})')

    def stop(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Stop syscall tracing"""
        return self._session.eval("Syscall.stop()")


class KCov:
    """KCov API wrapper - kernel coverage collection via Lua eval"""

    def __init__(self, session: 'RenefSession'):
        self._session = session

    def start(self, buf_size: int = 0) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Open KCOV and start coverage collection

        Args:
            buf_size: Buffer size (0 for default 256K entries)
        """
        code = f"""
_kcov = KCov.open({buf_size})
_kcov:enable()
print("ok")
"""
        return self._session.eval(code)

    def stop(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Stop coverage and close"""
        return self._session.eval("""
if _kcov then _kcov:disable(); _kcov:close(); _kcov = nil end
print("ok")
""")

    def collect(self) -> Optional[List[int]]:
        """Collect coverage PCs"""
        ok, out, _ = self._session.eval("""
if _kcov then
    local pcs = _kcov:collect()
    for _, pc in ipairs(pcs) do print(string.format("0x%x", pc)) end
else
    print("__NIL__")
end
""")
        if ok and out:
            out = out.strip()
            if out == "__NIL__":
                return None
            return [int(line, 16) for line in out.split('\n') if line]
        return None

    def count(self) -> Optional[int]:
        """Get number of collected PCs"""
        ok, out, _ = self._session.eval("""
if _kcov then print(_kcov:count()) else print(-1) end
""")
        if ok and out:
            try:
                return int(out.strip())
            except ValueError:
                return None
        return None

    def reset(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Reset coverage buffer"""
        return self._session.eval("""
if _kcov then _kcov:reset() end
print("ok")
""")


class RenefSession:
    """Session wrapper for attached/spawned process"""

    def __init__(self, handle, lib):
        self._handle = handle
        self._lib = lib
        self._memory = None
        self._module = None
        self._thread = None
        self._os = None
        self._file = None
        self._syscall = None
        self._kcov = None

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        if self._handle:
            self.watch_stop()
            self._lib.renef_session_close(self._handle)
            self._handle = None

    @property
    def pid(self) -> int:
        """Get target process ID"""
        if not self._handle:
            return -1
        return self._lib.renef_session_pid(self._handle)

    @property
    def Memory(self) -> Memory:
        """Access Memory API"""
        if self._memory is None:
            self._memory = Memory(self)
        return self._memory

    @property
    def Module(self) -> Module:
        """Access Module API"""
        if self._module is None:
            self._module = Module(self)
        return self._module

    @property
    def Thread(self) -> Thread:
        """Access Thread API"""
        if self._thread is None:
            self._thread = Thread(self)
        return self._thread

    @property
    def OS(self) -> OS:
        """Access OS API"""
        if self._os is None:
            self._os = OS(self)
        return self._os

    @property
    def File(self) -> File:
        """Access File API"""
        if self._file is None:
            self._file = File(self)
        return self._file

    @property
    def Syscall(self) -> Syscall:
        """Access Syscall API"""
        if self._syscall is None:
            self._syscall = Syscall(self)
        return self._syscall

    @property
    def KCov(self) -> KCov:
        """Access KCov API"""
        if self._kcov is None:
            self._kcov = KCov(self)
        return self._kcov

    def eval(self, lua_code: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Execute Lua code

        Returns:
            (success, output, error)
        """
        if not self._handle:
            return (False, None, "Session closed")

        result = self._lib.renef_eval(self._handle, lua_code.encode())
        success = result.success != 0
        output = result.output.decode() if result.output else None
        error = result.error.decode() if result.error else None
        self._lib.renef_result_free(ctypes.byref(result))
        return (success, output, error)

    def load_script(self, path: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Load and execute Lua script file"""
        if not self._handle:
            return (False, None, "Session closed")

        result = self._lib.renef_load_script(self._handle, path.encode())
        success = result.success != 0
        output = result.output.decode() if result.output else None
        error = result.error.decode() if result.error else None
        self._lib.renef_result_free(ctypes.byref(result))
        return (success, output, error)

    def memscan(self, pattern: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Scan memory for hex pattern (e.g. 'FF 00 ?? 01')"""
        if not self._handle:
            return (False, None, "Session closed")

        result = self._lib.renef_memscan(self._handle, pattern.encode())
        success = result.success != 0
        output = result.output.decode() if result.output else None
        error = result.error.decode() if result.error else None
        self._lib.renef_result_free(ctypes.byref(result))
        return (success, output, error)

    def hook(self, lib: str, offset: int, on_enter: str = None, on_leave: str = None) -> int:
        """
        Install native hook

        Args:
            lib: Library name (e.g. "libc.so")
            offset: Offset from library base
            on_enter: Lua code for onEnter callback
            on_leave: Lua code for onLeave callback

        Returns:
            0 on success, -1 on failure
        """
        if not self._handle:
            return -1

        on_enter_b = on_enter.encode() if on_enter else None
        on_leave_b = on_leave.encode() if on_leave else None
        return self._lib.renef_hook(self._handle, lib.encode(), offset, on_enter_b, on_leave_b)

    def hook_java(self, class_name: str, method_name: str, signature: str,
                  on_enter: str = None, on_leave: str = None) -> int:
        """
        Install Java method hook

        Args:
            class_name: Java class (e.g. "com/example/MainActivity")
            method_name: Method name
            signature: JNI signature (e.g. "(Ljava/lang/String;)V")
            on_enter: Lua code for onEnter callback
            on_leave: Lua code for onLeave callback

        Returns:
            0 on success, -1 on failure
        """
        if not self._handle:
            return -1

        on_enter_b = on_enter.encode() if on_enter else None
        on_leave_b = on_leave.encode() if on_leave else None
        return self._lib.renef_hook_java(
            self._handle,
            class_name.encode(),
            method_name.encode(),
            signature.encode(),
            on_enter_b,
            on_leave_b
        )

    def unhook(self, hook_id: int) -> int:
        """Remove hook by ID"""
        if not self._handle:
            return -1
        return self._lib.renef_unhook(self._handle, hook_id)

    def hooks(self) -> str:
        """List active hooks"""
        if not self._handle:
            return ""

        result = self._lib.renef_hooks_list(self._handle)
        output = result.output.decode() if result.output else ""
        self._lib.renef_result_free(ctypes.byref(result))
        return output

    def watch_start(self, callback) -> int:
        """
        Start real-time watch of hook output

        Args:
            callback: Function that receives (message: bytes, length: int)

        Returns:
            0 on success, -1 on failure
        """
        if not self._handle:
            return -1

        def _wrapper(msg, length, _user_data):
            callback(msg[:length])

        self._watch_cb = RenefMessageCallback(_wrapper)
        return self._lib.renef_watch_start(self._handle, self._watch_cb, None)

    def watch_stop(self):
        """Stop real-time watch"""
        if self._handle and hasattr(self, '_watch_cb') and self._watch_cb:
            self._lib.renef_watch_stop(self._handle)
            self._watch_cb = None


class Renef:
    """Main Renef client"""

    def __init__(self, library_path: str = None):
        if library_path is None:
            library_path = _find_library()

        if library_path is None:
            raise RuntimeError(
                "Could not find librenef.so. "
                "Build with: cd build && cmake .. && make renef_shared"
            )

        self._lib = ctypes.CDLL(library_path)
        self._setup_functions()

    def _setup_functions(self):
        """Setup ctypes function signatures"""
        # Session management
        self._lib.renef_spawn.argtypes = [c_char_p, c_int]
        self._lib.renef_spawn.restype = c_void_p

        self._lib.renef_attach.argtypes = [c_int, c_int]
        self._lib.renef_attach.restype = c_void_p

        self._lib.renef_session_close.argtypes = [c_void_p]
        self._lib.renef_session_close.restype = None

        self._lib.renef_session_pid.argtypes = [c_void_p]
        self._lib.renef_session_pid.restype = c_int

        # Eval / Script
        self._lib.renef_eval.argtypes = [c_void_p, c_char_p]
        self._lib.renef_eval.restype = RenefResult

        self._lib.renef_load_script.argtypes = [c_void_p, c_char_p]
        self._lib.renef_load_script.restype = RenefResult

        self._lib.renef_memscan.argtypes = [c_void_p, c_char_p]
        self._lib.renef_memscan.restype = RenefResult

        # Module API
        self._lib.renef_module_find.argtypes = [c_void_p, c_char_p]
        self._lib.renef_module_find.restype = c_uint64

        self._lib.renef_module_list.argtypes = [c_void_p]
        self._lib.renef_module_list.restype = RenefResult

        self._lib.renef_module_exports.argtypes = [c_void_p, c_char_p]
        self._lib.renef_module_exports.restype = RenefResult

        self._lib.renef_module_symbols.argtypes = [c_void_p, c_char_p]
        self._lib.renef_module_symbols.restype = RenefResult

        # Memory API
        self._lib.renef_read_memory.argtypes = [c_void_p, c_uint64, c_size_t, POINTER(c_uint8)]
        self._lib.renef_read_memory.restype = c_ssize_t

        self._lib.renef_write_memory.argtypes = [c_void_p, c_uint64, POINTER(c_uint8), c_size_t]
        self._lib.renef_write_memory.restype = c_ssize_t

        self._lib.renef_read_u8.argtypes = [c_void_p, c_uint64]
        self._lib.renef_read_u8.restype = c_uint8

        self._lib.renef_read_u16.argtypes = [c_void_p, c_uint64]
        self._lib.renef_read_u16.restype = c_uint16

        self._lib.renef_read_u32.argtypes = [c_void_p, c_uint64]
        self._lib.renef_read_u32.restype = c_uint32

        self._lib.renef_read_u64.argtypes = [c_void_p, c_uint64]
        self._lib.renef_read_u64.restype = c_uint64

        self._lib.renef_read_string.argtypes = [c_void_p, c_uint64, c_size_t]
        self._lib.renef_read_string.restype = RenefResult

        self._lib.renef_write_u8.argtypes = [c_void_p, c_uint64, c_uint8]
        self._lib.renef_write_u8.restype = c_int

        self._lib.renef_write_u16.argtypes = [c_void_p, c_uint64, c_uint16]
        self._lib.renef_write_u16.restype = c_int

        self._lib.renef_write_u32.argtypes = [c_void_p, c_uint64, c_uint32]
        self._lib.renef_write_u32.restype = c_int

        self._lib.renef_write_u64.argtypes = [c_void_p, c_uint64, c_uint64]
        self._lib.renef_write_u64.restype = c_int

        # Thread API
        self._lib.renef_thread_backtrace.argtypes = [c_void_p]
        self._lib.renef_thread_backtrace.restype = RenefResult

        self._lib.renef_thread_id.argtypes = [c_void_p]
        self._lib.renef_thread_id.restype = c_uint64

        # Hook API
        self._lib.renef_hook.argtypes = [c_void_p, c_char_p, c_uint64, c_char_p, c_char_p]
        self._lib.renef_hook.restype = c_int

        self._lib.renef_hook_java.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]
        self._lib.renef_hook_java.restype = c_int

        self._lib.renef_unhook.argtypes = [c_void_p, c_int]
        self._lib.renef_unhook.restype = c_int

        self._lib.renef_hooks_list.argtypes = [c_void_p]
        self._lib.renef_hooks_list.restype = RenefResult

        # Watch API
        self._lib.renef_watch_start.argtypes = [c_void_p, RenefMessageCallback, c_void_p]
        self._lib.renef_watch_start.restype = c_int

        self._lib.renef_watch_stop.argtypes = [c_void_p]
        self._lib.renef_watch_stop.restype = None

        # Utility
        self._lib.renef_result_free.argtypes = [POINTER(RenefResult)]
        self._lib.renef_result_free.restype = None

    def spawn(self, package: str, hook_type: int = 0) -> Optional[RenefSession]:
        """
        Spawn app and inject

        Args:
            package: Package name (e.g. "com.example.app")
            hook_type: 0=trampoline, 1=plt

        Returns:
            RenefSession or None on failure
        """
        handle = self._lib.renef_spawn(package.encode(), hook_type)
        if not handle:
            return None
        return RenefSession(handle, self._lib)

    def attach(self, pid: int, hook_type: int = 0) -> Optional[RenefSession]:
        """
        Attach to running process

        Args:
            pid: Process ID
            hook_type: 0=trampoline, 1=plt

        Returns:
            RenefSession or None on failure
        """
        handle = self._lib.renef_attach(pid, hook_type)
        if not handle:
            return None
        return RenefSession(handle, self._lib)


if __name__ == "__main__":
    print("Renef Python Binding")
    print("=" * 40)

    try:
        lib_path = _find_library()
        print(f"[+] Library: {lib_path}")
        r = Renef(lib_path)
        print("[+] Loaded successfully")
    except Exception as e:
        print(f"[-] Error: {e}")
        exit(1)

    print()
    print("Usage:")
    print("  from renef import Renef")
    print("  r = Renef()")
    print("  session = r.spawn('com.example.app')")
    print()
    print("  # Module API")
    print("  base = session.Module.find('libc.so')")
    print("  modules = session.Module.list()")
    print("  exports = session.Module.exports('libc.so')")
    print()
    print("  # Memory API")
    print("  val = session.Memory.read_u32(0x12345678)")
    print("  session.Memory.write_u32(0x12345678, 0xDEADBEEF)")
    print("  data = session.Memory.read(0x12345678, 16)")
    print()
    print("  # Hook API")
    print("  session.hook('libc.so', 0x1234, 'print(args[0])', 'print(retval)')")
    print("  session.hook_java('com/example/Main', 'test', '()V', 'print(\"called\")')")
    print()
    print("  # Eval")
    print("  ok, out, err = session.eval('print(1+1)')")

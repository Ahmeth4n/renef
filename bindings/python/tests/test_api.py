"""
Unit tests for Renef Python binding API wrappers.

These tests mock the underlying librenef C library to verify that
the Python wrapper classes generate correct Lua code, parse return
values properly, and handle edge cases (None, errors, empty results).

No device or librenef.so required.
"""

import unittest
from unittest.mock import MagicMock, patch, PropertyMock
import ctypes
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from renef.core import (
    RenefResult, RenefSession, Memory, Module, Thread,
    OS, File, Syscall, KCov,
)


def make_result(success=1, output=None, error=None):
    """Helper to create a mock RenefResult"""
    r = MagicMock(spec=RenefResult)
    r.success = success
    r.output = output.encode() if output else None
    r.error = error.encode() if error else None
    return r


class MockSession:
    """A minimal mock of RenefSession that captures eval calls"""

    def __init__(self):
        self.eval_calls = []
        self._handle = MagicMock()
        self._lib = MagicMock()

    def eval(self, lua_code):
        self.eval_calls.append(lua_code)
        if hasattr(self, '_eval_response'):
            return self._eval_response
        return (True, None, None)

    def set_eval_response(self, success, output, error=None):
        self._eval_response = (success, output, error)


# ============================================================
# OS API Tests
# ============================================================
class TestOSAPI(unittest.TestCase):

    def setUp(self):
        self.mock = MockSession()
        self.os = OS(self.mock)

    def test_getpid(self):
        self.mock.set_eval_response(True, "12345\n")
        result = self.os.getpid()
        self.assertEqual(result, 12345)
        self.assertIn("OS.getpid()", self.mock.eval_calls[-1])

    def test_getpid_failure(self):
        self.mock.set_eval_response(False, None, "error")
        result = self.os.getpid()
        self.assertIsNone(result)

    def test_kill(self):
        self.mock.set_eval_response(True, "0\n")
        result = self.os.kill(1234, 15)
        self.assertEqual(result, 0)
        self.assertIn("OS.kill(1234, 15)", self.mock.eval_calls[-1])

    def test_kill_invalid(self):
        self.mock.set_eval_response(True, "-1\n")
        result = self.os.kill(99999, 9)
        self.assertEqual(result, -1)

    def test_tgkill(self):
        self.mock.set_eval_response(True, "0\n")
        result = self.os.tgkill(100, 101, 9)
        self.assertEqual(result, 0)
        self.assertIn("OS.tgkill(100, 101, 9)", self.mock.eval_calls[-1])

    def test_listdir(self):
        self.mock.set_eval_response(True, "file1\nfile2\nfile3\n")
        result = self.os.listdir("/tmp")
        self.assertEqual(result, ["file1", "file2", "file3"])

    def test_listdir_nil(self):
        self.mock.set_eval_response(True, "__NIL__\n")
        result = self.os.listdir("/nonexistent")
        self.assertIsNone(result)

    def test_listdir_empty(self):
        self.mock.set_eval_response(True, "\n")
        result = self.os.listdir("/empty")
        self.assertEqual(result, [])

    def test_listdir_eval_failure(self):
        self.mock.set_eval_response(False, None, "error")
        result = self.os.listdir("/tmp")
        self.assertIsNone(result)


# ============================================================
# File API Tests
# ============================================================
class TestFileAPI(unittest.TestCase):

    def setUp(self):
        self.mock = MockSession()
        self.file = File(self.mock)

    def test_read(self):
        self.mock.set_eval_response(True, "hello world\n")
        result = self.file.read("/etc/hostname")
        self.assertEqual(result, "hello world")

    def test_read_nil(self):
        self.mock.set_eval_response(True, "__NIL__\n")
        result = self.file.read("/nonexistent")
        self.assertIsNone(result)

    def test_exists_true(self):
        self.mock.set_eval_response(True, "true\n")
        self.assertTrue(self.file.exists("/etc/hosts"))

    def test_exists_false(self):
        self.mock.set_eval_response(True, "false\n")
        self.assertFalse(self.file.exists("/nonexistent"))

    def test_readlink(self):
        self.mock.set_eval_response(True, "/usr/lib/libc.so.6\n")
        result = self.file.readlink("/usr/lib/libc.so")
        self.assertEqual(result, "/usr/lib/libc.so.6")

    def test_readlink_nil(self):
        self.mock.set_eval_response(True, "__NIL__\n")
        result = self.file.readlink("/not_a_link")
        self.assertIsNone(result)

    def test_fdpath(self):
        self.mock.set_eval_response(True, "/dev/null\n")
        result = self.file.fdpath(3)
        self.assertEqual(result, "/dev/null")

    def test_fdpath_nil(self):
        self.mock.set_eval_response(True, "__NIL__\n")
        result = self.file.fdpath(999)
        self.assertIsNone(result)

    def test_write_success(self):
        self.mock.set_eval_response(True, "true\n")
        self.assertTrue(self.file.write("/tmp/dump.bin", 0x7f000000, 4096))

    def test_write_failure(self):
        self.mock.set_eval_response(True, "false\n")
        self.assertFalse(self.file.write("/readonly/file", 0x7f000000, 4096))


# ============================================================
# Syscall API Tests
# ============================================================
class TestSyscallAPI(unittest.TestCase):

    def setUp(self):
        self.mock = MockSession()
        self.syscall = Syscall(self.mock)

    def test_trace_single(self):
        self.mock.set_eval_response(True, "Tracing openat\n")
        ok, out, err = self.syscall.trace("openat")
        self.assertTrue(ok)
        lua = self.mock.eval_calls[-1]
        self.assertIn('Syscall.trace("openat")', lua)

    def test_trace_multiple(self):
        self.mock.set_eval_response(True, "Tracing 3 syscalls\n")
        self.syscall.trace("openat", "read", "write")
        lua = self.mock.eval_calls[-1]
        self.assertIn('"openat"', lua)
        self.assertIn('"read"', lua)
        self.assertIn('"write"', lua)

    def test_trace_category(self):
        self.mock.set_eval_response(True, "Tracing 5 file syscalls\n")
        self.syscall.trace_category("file")
        lua = self.mock.eval_calls[-1]
        self.assertIn('category="file"', lua)

    def test_stop(self):
        self.mock.set_eval_response(True, "ok\n")
        ok, out, err = self.syscall.stop()
        self.assertTrue(ok)
        self.assertIn("Syscall.stop()", self.mock.eval_calls[-1])


# ============================================================
# KCov API Tests
# ============================================================
class TestKCovAPI(unittest.TestCase):

    def setUp(self):
        self.mock = MockSession()
        self.kcov = KCov(self.mock)

    def test_start_default(self):
        self.mock.set_eval_response(True, "ok\n")
        ok, out, err = self.kcov.start()
        self.assertTrue(ok)
        lua = self.mock.eval_calls[-1]
        self.assertIn("KCov.open(0)", lua)
        self.assertIn(":enable()", lua)

    def test_start_custom_size(self):
        self.mock.set_eval_response(True, "ok\n")
        self.kcov.start(buf_size=65536)
        lua = self.mock.eval_calls[-1]
        self.assertIn("KCov.open(65536)", lua)

    def test_stop(self):
        self.mock.set_eval_response(True, "ok\n")
        ok, out, err = self.kcov.stop()
        self.assertTrue(ok)
        lua = self.mock.eval_calls[-1]
        self.assertIn(":disable()", lua)
        self.assertIn(":close()", lua)

    def test_collect(self):
        self.mock.set_eval_response(True, "0xffffff8008a1234\n0xffffff8008a5678\n")
        pcs = self.kcov.collect()
        self.assertEqual(len(pcs), 2)
        self.assertEqual(pcs[0], 0xffffff8008a1234)
        self.assertEqual(pcs[1], 0xffffff8008a5678)

    def test_collect_nil(self):
        self.mock.set_eval_response(True, "__NIL__\n")
        result = self.kcov.collect()
        self.assertIsNone(result)

    def test_count(self):
        self.mock.set_eval_response(True, "42\n")
        result = self.kcov.count()
        self.assertEqual(result, 42)

    def test_count_no_kcov(self):
        self.mock.set_eval_response(True, "-1\n")
        result = self.kcov.count()
        self.assertEqual(result, -1)

    def test_reset(self):
        self.mock.set_eval_response(True, "ok\n")
        ok, out, err = self.kcov.reset()
        self.assertTrue(ok)


# ============================================================
# RenefSession Property Tests
# ============================================================
class TestSessionProperties(unittest.TestCase):

    def setUp(self):
        self.lib = MagicMock()
        self.session = RenefSession(MagicMock(), self.lib)

    def test_os_property_returns_os(self):
        self.assertIsInstance(self.session.OS, OS)

    def test_file_property_returns_file(self):
        self.assertIsInstance(self.session.File, File)

    def test_syscall_property_returns_syscall(self):
        self.assertIsInstance(self.session.Syscall, Syscall)

    def test_kcov_property_returns_kcov(self):
        self.assertIsInstance(self.session.KCov, KCov)

    def test_memory_property_returns_memory(self):
        self.assertIsInstance(self.session.Memory, Memory)

    def test_module_property_returns_module(self):
        self.assertIsInstance(self.session.Module, Module)

    def test_thread_property_returns_thread(self):
        self.assertIsInstance(self.session.Thread, Thread)

    def test_properties_are_cached(self):
        os1 = self.session.OS
        os2 = self.session.OS
        self.assertIs(os1, os2)

        file1 = self.session.File
        file2 = self.session.File
        self.assertIs(file1, file2)

    def test_pid_returns_int(self):
        self.lib.renef_session_pid.return_value = 1234
        self.assertEqual(self.session.pid, 1234)

    def test_pid_closed_session(self):
        self.session._handle = None
        self.assertEqual(self.session.pid, -1)


# ============================================================
# RenefSession eval/hook Tests
# ============================================================
class TestSessionMethods(unittest.TestCase):

    def setUp(self):
        self.lib = MagicMock()
        # ctypes.byref can't handle MagicMock, so make result_free a no-op
        self.lib.renef_result_free = MagicMock()
        self.session = RenefSession(MagicMock(), self.lib)
        # Patch ctypes.byref in the module under test
        self._byref_patcher = patch("renef.core.ctypes.byref", side_effect=lambda x: x)
        self._byref_patcher.start()

    def tearDown(self):
        self._byref_patcher.stop()

    def test_eval_success(self):
        self.lib.renef_eval.return_value = make_result(1, "hello")
        ok, out, err = self.session.eval("print('hello')")
        self.assertTrue(ok)
        self.assertEqual(out, "hello")
        self.assertIsNone(err)

    def test_eval_failure(self):
        self.lib.renef_eval.return_value = make_result(0, None, "syntax error")
        ok, out, err = self.session.eval("bad code")
        self.assertFalse(ok)
        self.assertEqual(err, "syntax error")

    def test_eval_closed_session(self):
        self.session._handle = None
        ok, out, err = self.session.eval("print(1)")
        self.assertFalse(ok)
        self.assertEqual(err, "Session closed")

    def test_hook(self):
        self.lib.renef_hook.return_value = 0
        result = self.session.hook("libc.so", 0x1234, on_enter="print(args[0])")
        self.assertEqual(result, 0)

    def test_hook_closed(self):
        self.session._handle = None
        result = self.session.hook("libc.so", 0x1234)
        self.assertEqual(result, -1)

    def test_hook_java(self):
        self.lib.renef_hook_java.return_value = 0
        result = self.session.hook_java(
            "com/example/Main", "test", "()V",
            on_enter="print('called')"
        )
        self.assertEqual(result, 0)

    def test_unhook(self):
        self.lib.renef_unhook.return_value = 0
        self.assertEqual(self.session.unhook(0), 0)

    def test_unhook_closed(self):
        self.session._handle = None
        self.assertEqual(self.session.unhook(0), -1)

    def test_load_script(self):
        self.lib.renef_load_script.return_value = make_result(1, "loaded")
        ok, out, err = self.session.load_script("/path/to/script.lua")
        self.assertTrue(ok)
        self.assertEqual(out, "loaded")

    def test_memscan(self):
        self.lib.renef_memscan.return_value = make_result(1, "found 3 results")
        ok, out, err = self.session.memscan("FD 7B ?? A9")
        self.assertTrue(ok)
        self.assertIn("3 results", out)

    def test_hooks_list(self):
        self.lib.renef_hooks_list.return_value = make_result(1, "hook#0 libc.so+0x1234")
        output = self.session.hooks()
        self.assertIn("hook#0", output)

    def test_close_idempotent(self):
        self.session.close()
        self.session.close()  # should not crash


# ============================================================
# Context Manager Test
# ============================================================
class TestContextManager(unittest.TestCase):

    def test_with_block(self):
        lib = MagicMock()
        handle = MagicMock()
        with RenefSession(handle, lib) as s:
            self.assertIsNotNone(s._handle)
        self.assertIsNone(s._handle)
        lib.renef_session_close.assert_called_once()


if __name__ == "__main__":
    unittest.main()

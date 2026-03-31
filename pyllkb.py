import ctypes
import threading
from collections import defaultdict
from collections.abc import Callable
from contextlib import suppress
from ctypes import wintypes
from typing import Any

# WinAPI CONST
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105
WM_QUIT = 0x0012

if ctypes.sizeof(ctypes.c_void_p) == 8:
    ULONG_PTR = ctypes.c_ulonglong
else:
    ULONG_PTR = ctypes.c_ulong

LRESULT = wintypes.LPARAM
HOOKPROC = ctypes.CFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


# SAS键扫描码
SCAN_CTRLL = 29
SCAN_CTRLR = 29 + 256  # 285
SCAN_ALTL = 56
SCAN_ALTR = 56 + 256  # 312
SCAN_DEL = 83


# WinAPI函数绑定
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleHandleW.restype = wintypes.HMODULE
GetModuleHandleW.argtypes = [wintypes.LPCWSTR]

SetWindowsHookEx = user32.SetWindowsHookExW
SetWindowsHookEx.restype = wintypes.HHOOK
SetWindowsHookEx.argtypes = [ctypes.c_int, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD]

UnhookWindowsHookEx = user32.UnhookWindowsHookEx
UnhookWindowsHookEx.restype = wintypes.BOOL
UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]

CallNextHookEx = user32.CallNextHookEx
CallNextHookEx.restype = LRESULT
CallNextHookEx.argtypes = [wintypes.HHOOK, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]

GetMessage = user32.GetMessageW
GetMessage.restype = wintypes.BOOL
GetMessage.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]

TranslateMessage = user32.TranslateMessage
TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]

DispatchMessage = user32.DispatchMessageW
DispatchMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]

PostThreadMessage = user32.PostThreadMessageW
PostThreadMessage.restype = wintypes.BOOL
PostThreadMessage.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]


_hook_id = None
_callback_func = None
_thread = None
_press_callback: None | Callable[[int], Any] = None
_release_callback: None | Callable[[int], Any] = None

_state_lock = threading.Lock()
_key_states = defaultdict(bool)


def _llkh(nCode: int, wParam, lParam):
    if nCode >= 0:
        kbd_struct = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT))
        scan_code: int = kbd_struct.contents.scanCode

        key_down: bool = wParam in (WM_KEYDOWN, WM_SYSKEYDOWN)
        key_up: bool = wParam in (WM_KEYUP, WM_SYSKEYUP)

        sas_detected = False
        pending_release_for_sas = []
        mock_keydown_needed = False

        with _state_lock:
            if key_down and scan_code == SCAN_DEL:  # 判SAS
                if (_key_states.get(SCAN_CTRLL, False) or _key_states.get(SCAN_CTRLR, False)) and (
                    _key_states.get(SCAN_ALTL, False) or _key_states.get(SCAN_ALTR, False)
                ):
                    sas_detected = True
                    for code in [SCAN_CTRLL, SCAN_CTRLR, SCAN_ALTL, SCAN_ALTR]:
                        if _key_states.get(code, False):
                            pending_release_for_sas.append(code)
                    pending_release_for_sas.append(SCAN_DEL)
                    _key_states[SCAN_CTRLL] = False
                    _key_states[SCAN_CTRLR] = False
                    _key_states[SCAN_ALTL] = False
                    _key_states[SCAN_ALTR] = False
                    _key_states[SCAN_DEL] = False

            if not sas_detected:
                if key_down:
                    _key_states[scan_code] = True
                elif key_up:
                    if not _key_states.get(scan_code, False):
                        mock_keydown_needed = True

        if sas_detected and _release_callback:
            for code in pending_release_for_sas:
                with suppress(Exception):
                    _release_callback(code)
        elif key_down and _press_callback:
            with suppress(Exception):
                _press_callback(scan_code)
        elif key_up:
            if mock_keydown_needed:
                if _press_callback:
                    with suppress(Exception):
                        with _state_lock:
                            _key_states[scan_code] = True
                        _press_callback(scan_code)
                if _release_callback:
                    with suppress(Exception):
                        with _state_lock:
                            _key_states[scan_code] = False
                        _release_callback(scan_code)
            elif _release_callback:
                with suppress(Exception):
                    _release_callback(scan_code)

    return CallNextHookEx(None, nCode, wParam, lParam)


def _hook():
    global _hook_id, _callback_func
    h_instance = GetModuleHandleW(None)
    _callback_func = HOOKPROC(_llkh)  # 防GC
    _hook_id = SetWindowsHookEx(WH_KEYBOARD_LL, _callback_func, h_instance, 0)
    if not _hook_id:
        raise RuntimeError(f"KB: 无法安装钩子: {kernel32.GetLastError()}")


def _unhook():
    global _hook_id, _callback_func
    if _hook_id:
        UnhookWindowsHookEx(_hook_id)
        _hook_id = None
        _callback_func = None


def _msgloop():
    msg = wintypes.MSG()
    try:
        _hook()
        while GetMessage(ctypes.byref(msg), None, 0, 0) != 0:
            if msg.message == WM_QUIT:
                break
            TranslateMessage(ctypes.byref(msg))
            DispatchMessage(ctypes.byref(msg))
    finally:
        _unhook()
        with _state_lock:
            _key_states.clear()


def set_press_callback(func: Callable[[int], Any]):
    global _press_callback
    _press_callback = func


def set_release_callback(func: Callable[[int], Any]):
    global _release_callback
    _release_callback = func


def get_current_keys() -> set[int]:
    with _state_lock:
        return {k for k, v in _key_states.items() if v}


def start():
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _thread = threading.Thread(target=_msgloop, daemon=True)
    _thread.start()


def stop():
    global _thread
    if _thread is not None and _thread.is_alive():
        if _thread.ident:
            PostThreadMessage(_thread.ident, WM_QUIT, 0, 0)
        _thread.join(timeout=2.0)
        _thread = None

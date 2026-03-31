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


VK_LCONTROL = 0xA2
VK_RCONTROL = 0xA3
VK_LMENU = 0xA4
VK_RMENU = 0xA5  # O(1)人知道为啥ALT键的vk名称叫MENU
VK_DELETE = 0x2E

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
        vk: int = kbd_struct.contents.vkCode
        key_down: bool = wParam in (WM_KEYDOWN, WM_SYSKEYDOWN)
        key_up: bool = wParam in (WM_KEYUP, WM_SYSKEYUP)
        sas_detected = False
        pending_release_for_sas = []
        mock_keydown_needed = False

        with _state_lock:
            if key_down and vk == VK_DELETE:
                ctrl_pressed = _key_states.get(VK_LCONTROL, False) or _key_states.get(VK_RCONTROL, False)
                alt_pressed = _key_states.get(VK_LMENU, False) or _key_states.get(VK_RMENU, False)

                if ctrl_pressed and alt_pressed:
                    sas_detected = True
                    for code in [VK_LCONTROL, VK_RCONTROL, VK_LMENU, VK_RMENU]:
                        if _key_states.get(code, False):
                            pending_release_for_sas.append(code)
                            _key_states[code] = False

                    pending_release_for_sas.append(VK_DELETE)
                    _key_states[VK_DELETE] = False

            if not sas_detected:
                if key_down:
                    _key_states[vk] = True
                elif key_up:
                    if not _key_states.get(vk, False):
                        mock_keydown_needed = True

            if sas_detected and _release_callback:
                for code in pending_release_for_sas:
                    with suppress(Exception):
                        _release_callback(code)
            elif key_down and _press_callback:
                with suppress(Exception):
                    _press_callback(vk)
            elif key_up:
                if mock_keydown_needed:
                    if _press_callback:
                        with suppress(Exception):
                            with _state_lock:
                                _key_states[vk] = True
                            _press_callback(vk)
                    if _release_callback:
                        with suppress(Exception):
                            with _state_lock:
                                _key_states[vk] = False
                            _release_callback(vk)
                elif _release_callback:
                    with suppress(Exception):
                        _release_callback(vk)

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


def set_press_callback(func: Callable[[int], Any] | None):
    global _press_callback
    _press_callback = func


def set_release_callback(func: Callable[[int], Any] | None):
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

import ctypes
import threading
from collections import defaultdict
from collections.abc import Callable
from ctypes import wintypes
from queue import Queue
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
VK_RMENU = 0xA5
VK_DELETE = 0x2E
VK_SCANCODE_255 = 255  # 兼容powertoys或者一些别的什么。
# 我不知道，但是至少目前可以明确确认的是powertoys会抛一个vk=255 sc=-255出来。
# 或许有别的程序也会用，那我不管了，我直接就是一个面对测试用例编程（bushi

_EVENT_PRESS = 0
_EVENT_RELEASE = 1
_EVENT_POISON = -1

# WinAPI 函数绑定
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
_hook_thread: threading.Thread | None = None
_consumer_thread: threading.Thread | None = None
_event_queue: Queue = Queue()
_consumer_stop = threading.Event()

_press_callback: None | Callable[[int], Any] = None
_release_callback: None | Callable[[int], Any] = None

_state_lock = threading.Lock()
_key_states: dict[int, bool] = defaultdict(bool)
_mock_released: set[int] = set()


def qput(events: list[tuple[int, int]]) -> None:
    for evt in events:
        _event_queue.put(evt)


def _llkh(nCode: int, wParam: int, lParam: int) -> int:
    if nCode < 0:
        return CallNextHookEx(None, nCode, wParam, lParam)

    kbd = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT))
    vk: int = kbd.contents.vkCode

    key_down: bool = wParam in (WM_KEYDOWN, WM_SYSKEYDOWN)
    key_up: bool = wParam in (WM_KEYUP, WM_SYSKEYUP)

    pending: list[tuple[int, int]] = []

    with _state_lock:
        if vk == VK_SCANCODE_255:
            for code, pressed in list(_key_states.items()):
                if pressed:
                    _key_states[code] = False
                    _mock_released.add(code)
                    pending.append((_EVENT_RELEASE, code))
            qput(pending)
            return CallNextHookEx(None, nCode, wParam, lParam)

        if key_down and vk == VK_DELETE:
            if (_key_states.get(VK_LCONTROL, False) or _key_states.get(VK_RCONTROL, False)) and (
                _key_states.get(VK_LMENU, False) or _key_states.get(VK_RMENU, False)
            ):
                for code in (VK_LCONTROL, VK_RCONTROL, VK_LMENU, VK_RMENU):
                    if _key_states.get(code, False):
                        pending.append((_EVENT_RELEASE, code))
                    _key_states[code] = False
                pending.append((_EVENT_RELEASE, VK_DELETE))
                _key_states[VK_DELETE] = False
                qput(pending)
                return CallNextHookEx(None, nCode, wParam, lParam)

        if key_down:
            _mock_released.discard(vk)
            _key_states[vk] = True
            pending.append((_EVENT_PRESS, vk))

        elif key_up:
            if vk in _mock_released:
                _mock_released.discard(vk)
            else:
                if not _key_states.get(vk, False):
                    pending.append((_EVENT_PRESS, vk))
                pending.append((_EVENT_RELEASE, vk))

    qput(pending)
    return CallNextHookEx(None, nCode, wParam, lParam)


def _consumer() -> None:
    while not _consumer_stop.is_set():
        event_typ, vk = _event_queue.get()

        if event_typ == _EVENT_POISON:
            break

        try:
            if event_typ == _EVENT_PRESS and _press_callback is not None:
                _press_callback(vk)
            elif event_typ == _EVENT_RELEASE and _release_callback is not None:
                _release_callback(vk)
        except Exception:
            pass
        finally:
            _event_queue.task_done()

    while not _event_queue.empty():  # 清空
        try:
            event_typ, vk = _event_queue.get_nowait()
        except Exception:
            break
        try:
            if event_typ == _EVENT_PRESS and _press_callback is not None:
                _press_callback(vk)
            elif event_typ == _EVENT_RELEASE and _release_callback is not None:
                _release_callback(vk)
        except Exception:
            pass


def _hook() -> None:
    global _hook_id, _callback_func
    h_instance = GetModuleHandleW(None)
    _callback_func = HOOKPROC(_llkh)
    _hook_id = SetWindowsHookEx(WH_KEYBOARD_LL, _callback_func, h_instance, 0)
    if not _hook_id:
        raise RuntimeError(f"KB: 无法安装钩子: {kernel32.GetLastError()}")


def _unhook() -> None:
    global _hook_id, _callback_func
    if _hook_id:
        UnhookWindowsHookEx(_hook_id)
    _hook_id = None
    _callback_func = None


def _msgloop() -> None:
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
            _mock_released.clear()


def set_press_callback(func: Callable[[int], Any] | None) -> None:
    global _press_callback
    _press_callback = func


def set_release_callback(func: Callable[[int], Any] | None) -> None:
    global _release_callback
    _release_callback = func


def get_current_keys() -> set[int]:
    with _state_lock:
        return {k for k, v in _key_states.items() if v}


def start() -> None:
    global _hook_thread, _consumer_thread
    if _hook_thread is not None and _hook_thread.is_alive():
        return

    _consumer_stop.clear()
    _consumer_thread = threading.Thread(target=_consumer, daemon=True)
    _consumer_thread.start()
    _hook_thread = threading.Thread(target=_msgloop, daemon=True)
    _hook_thread.start()


def stop() -> None:
    global _hook_thread, _consumer_thread

    _consumer_stop.set()
    _event_queue.put((_EVENT_POISON, 0))
    if _consumer_thread is not None and _consumer_thread.is_alive():
        _consumer_thread.join(timeout=2.0)
    _consumer_thread = None
    if _hook_thread is not None and _hook_thread.is_alive():
        if _hook_thread.ident:
            PostThreadMessage(_hook_thread.ident, WM_QUIT, 0, 0)
        _hook_thread.join(timeout=2.0)
    _hook_thread = None
    while not _event_queue.empty():
        try:
            _event_queue.get_nowait()
        except Exception:
            break

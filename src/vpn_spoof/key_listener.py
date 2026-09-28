import sys
import time
import os
import threading

CYRILLIC_TO_LATIN = {
    'й': 'q', 'ц': 'w', 'у': 'e', 'к': 'r', 'е': 't', 'н': 'y', 'г': 'u',
    'ш': 'i', 'щ': 'o', 'з': 'p', 'ф': 'a', 'ы': 's', 'в': 'd', 'а': 'f',
    'п': 'g', 'р': 'h', 'о': 'j', 'л': 'k', 'д': 'l', 'я': 'z', 'ч': 'x',
    'с': 'c', 'м': 'v', 'и': 'b', 'т': 'n', 'ь': 'm'
}

_last_ctrl_c_time = 0.0

def check_double_ctrl_c() -> bool:
    """
    Checks if Ctrl+C was pressed twice within 2.5 seconds to fully exit.
    1st press: prints warning and returns False.
    2nd press: exits entire application immediately.
    """
    global _last_ctrl_c_time
    now = time.time()
    if now - _last_ctrl_c_time < 2.5:
        sys.stdout.write("\n\033[91m[!] Подтверждено. Полный выход из программы.\033[0m\n")
        sys.stdout.flush()
        os._exit(0)
    else:
        _last_ctrl_c_time = now
        sys.stdout.write("\n\033[93m[!] Нажмите Ctrl+C ещё раз в течение 2 секунд для выхода из программы (или 'q' для возврата назад)\033[0m\n")
        sys.stdout.flush()
        return False

def normalize_key(ch: str) -> str:
    """Normalize lowercase key, mapping Russian layout characters to Latin equivalents."""
    c = ch.lower()
    return CYRILLIC_TO_LATIN.get(c, c)

def get_single_key() -> str:
    """Read a single keypress without waiting for Enter, supporting Unicode & layout mapping."""
    if not sys.stdin or not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty():
        line = sys.stdin.readline()
        if not line:
            raise EOFError
        raw = line.strip()[:1]
        return normalize_key(raw)

    if sys.platform == "win32":
        import msvcrt
        while True:
            ch = msvcrt.getwch()
            if ch == '\x03':  # Ctrl+C
                check_double_ctrl_c()
                continue
            if ch in ('\x00', '\xe0'):
                # Extended key (arrows, F-keys, etc.), consume the second char
                if msvcrt.kbhit():
                    msvcrt.getwch()
                continue
            if ch in ('\r', '\n'):
                return '\n'
            return normalize_key(ch)
    else:
        import tty
        import termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == '\x03':  # Ctrl+C
                check_double_ctrl_c()
                return ""
            return normalize_key(ch)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def wait_for_cancel(stop_event: threading.Event, timeout_step: float = 0.1) -> str:
    """
    Waits until stop_event is set OR user presses 'q'/'й', '0', Esc, or Ctrl+C.
    'q'/'й', '0', Esc returns 'back' to go to the previous step.
    Ctrl+C warns on 1st press, and exits the entire program on 2nd press.
    """
    if not sys.stdin or not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty():
        try:
            while not stop_event.is_set():
                time.sleep(timeout_step)
        except (KeyboardInterrupt, SystemExit):
            pass
        return 'stop'

    if sys.platform == "win32":
        import msvcrt
        while not stop_event.is_set():
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch == '\x03':  # Ctrl+C
                    check_double_ctrl_c()
                    continue
                if ch in ('\x00', '\xe0'):
                    if msvcrt.kbhit():
                        msvcrt.getwch()
                    continue
                c = normalize_key(ch)
                if c in ('q', '0', '\x1b'):
                    return 'back'
            time.sleep(timeout_step)
        return 'stop'
    else:
        import select
        import tty
        import termios

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while not stop_event.is_set():
                r, _, _ = select.select([sys.stdin], [], [], timeout_step)
                if r:
                    ch = sys.stdin.read(1)
                    if ch == '\x03':  # Ctrl+C
                        check_double_ctrl_c()
                        continue
                    c = normalize_key(ch)
                    if c in ('q', '0', '\x1b'):
                        return 'back'
            return 'stop'
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def wait_key(prompt: str = "\nНажмите любую клавишу для возврата в меню..."):
    """Wait for a single keypress, or return immediately if non-interactive."""
    sys.stdout.write(f"\033[90m{prompt}\033[0m")
    sys.stdout.flush()
    try:
        get_single_key()
    except (KeyboardInterrupt, EOFError):
        pass
    sys.stdout.write("\n")
    sys.stdout.flush()

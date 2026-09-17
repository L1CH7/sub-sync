import sys
import time
import threading

def get_single_key() -> str:
    """Read a single keypress without waiting for Enter."""
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if not line:
            raise EOFError
        return line.strip()[:1].lower()

    if sys.platform == "win32":
        import msvcrt
        while True:
            ch = msvcrt.getch()
            if ch == b'\x03':  # Ctrl+C
                raise KeyboardInterrupt
            if ch in (b'\x00', b'\xe0'):
                msvcrt.getch()  # consume extended key prefix
                continue
            try:
                return ch.decode("utf-8", errors="ignore").lower()
            except Exception:
                return ""
    else:
        import tty
        import termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == '\x03':  # Ctrl+C
                raise KeyboardInterrupt
            return ch.lower()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def wait_for_cancel(stop_event: threading.Event, timeout_step: float = 0.1) -> str:
    """
    Waits until stop_event is set OR user presses 'q', '0', Esc, or Ctrl+C.
    In non-interactive mode (daemon/service where stdin is not a tty),
    blocks until stop_event is set or process receives a signal.
    """
    if not sys.stdin or not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty():
        try:
            while not stop_event.is_set():
                time.sleep(timeout_step)
        except (KeyboardInterrupt, SystemExit):
            pass
        return 'stop'

    if sys.platform == "win32":

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
                        raise KeyboardInterrupt
                    if ch.lower() in ('q', '0', '\x1b'):
                        return 'back'
            return 'stop'
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def wait_key(prompt: str = "\nНажмите любую клавишу для возврата в меню..."):
    """Wait for a single keypress, or return immediately if non-interactive."""
    from rich.console import Console
    console = Console(legacy_windows=False)
    console.print(f"[dim]{prompt}[/dim]", end="", highlight=False)
    sys.stdout.flush()
    try:
        get_single_key()
    except (KeyboardInterrupt, EOFError):
        raise
    print()

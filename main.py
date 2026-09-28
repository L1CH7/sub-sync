import sys
import os
from pathlib import Path

# Fix Windows console UTF-8 encoding and enable ANSI virtual terminal processing
if sys.platform == "win32":
    os.system("chcp 65001 >nul 2>&1")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        hOut = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(hOut, ctypes.byref(mode)):
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(hOut, mode.value | 0x0004)
    except Exception:
        pass

# Ensure src is in python path
src_dir = Path(__file__).absolute().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from vpn_spoof.cli import main

if __name__ == "__main__":
    main()

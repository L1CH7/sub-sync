import sys
import os
from pathlib import Path

# Fix Windows console UTF-8 encoding (CP1251 / CP866)
if sys.platform == "win32":
    os.system("chcp 65001 >nul 2>&1")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")

# Ensure src is in python path
src_dir = Path(__file__).absolute().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from vpn_spoof.cli import main

if __name__ == "__main__":
    main()

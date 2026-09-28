import qrcode
import sys
import os
from pathlib import Path

def render_compact_terminal_qr(data: str, use_ansi: bool = True) -> str:
    """
    Renders a compact, high-contrast QR code using Unicode half-blocks (▀, ▄, █, ' ').
    Each character cell represents two vertical QR modules (top and bottom).
    Because console characters are roughly twice as tall as they are wide,
    this creates virtually square modules and reduces width and height by 50%,
    preventing any line-wrapping on standard 80-column terminals and fitting on screen
    without vertical scrolling.
    
    When use_ansi=True, wraps with ANSI white background / black text (\033[47;30m)
    to guarantee high contrast regardless of terminal theme (e.g. blue PowerShell or dark/light theme).
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    
    height = len(matrix)
    width = len(matrix[0])
    lines = []
    
    ansi_prefix = "\033[47;30m" if use_ansi else ""
    ansi_suffix = "\033[0m" if use_ansi else ""
    
    for r in range(0, height, 2):
        row_chars = []
        for c in range(width):
            top = matrix[r][c]
            bot = matrix[r + 1][c] if r + 1 < height else False
            
            if use_ansi:
                # In ANSI black-on-white: ' ' is white, '█' is black,
                # '▀' is top black / bot white, '▄' is top white / bot black.
                if not top and not bot:
                    row_chars.append(" ")
                elif top and bot:
                    row_chars.append("█")
                elif top and not bot:
                    row_chars.append("▀")
                else:
                    row_chars.append("▄")
            else:
                # Plain text fallback (assumes dark terminal background)
                if not top and not bot:
                    row_chars.append("█")
                elif top and bot:
                    row_chars.append(" ")
                elif top and not bot:
                    row_chars.append("▄")
                else:
                    row_chars.append("▀")
        
        lines.append(f"{ansi_prefix}{''.join(row_chars)}{ansi_suffix}")
    
    return "\n".join(lines)

def render_solid_terminal_qr(data: str) -> str:
    """Backward compatibility alias pointing to the compact half-block renderer."""
    return render_compact_terminal_qr(data)

def save_qr_image(data: str, out_path: Path | str) -> str:
    """Saves QR code as a PNG image for alternative viewing."""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        out_p = Path(out_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        img.save(str(out_p))
        return str(out_p)
    except Exception:
        return ""

def print_qr_banner(title: str, url: str, save_path: Path | str | None = None):
    print("\n" + "=" * 54)
    print(f"  {title}")
    print(f"  URL: {url}")
    print("=" * 54 + "\n")
    print(render_compact_terminal_qr(url))
    print("\n" + "=" * 54)
    if save_path:
        saved = save_qr_image(url, save_path)
        if saved:
            print(f"  [i] QR-код также сохранён в файл: {saved}")
    print()

import qrcode
import sys
import os

def render_solid_terminal_qr(data: str) -> str:
    """
    Renders QR code using double inverted unicode full blocks (██ and space).
    To ensure no vertical gaps from terminal line-height/font spacing,
    we use standard 2-character wide blocks.
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

    lines = []
    for row in matrix:
        lines.append("".join("  " if cell else "██" for cell in row))
    return "\n".join(lines)

def print_qr_banner(title: str, url: str):
    print("\n" + "=" * 54)
    print(f"  {title}")
    print(f"  URL: {url}")
    print("=" * 54 + "\n")
    print(render_solid_terminal_qr(url))
    print("\n" + "=" * 54 + "\n")

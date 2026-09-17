import sys
import os
import time
import subprocess
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.text import Text
from rich import box

from .unified_setup import UnifiedSetupServer
from .proxy_service import SpoofProxyServer
from .bundle_transfer import BundleTransfer
from .config_store import ConfigStore
from .net_utils import get_best_local_ip

console = Console(legacy_windows=False)

def clear_screen():
    os.system("cls" if sys.platform == "win32" else "clear")

from .key_listener import get_single_key as get_key, wait_key

def is_service_installed() -> bool:
    if sys.platform == "win32":
        try:
            startup_folder = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if (startup_folder / "VPNSpoofProxy.lnk").exists():
                return True
        except Exception:
            pass
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "Get-ScheduledTask -TaskName 'VPNSpoofProxy' -ErrorAction SilentlyContinue"],
                capture_output=True, text=True, timeout=2
            )
            return "VPNSpoofProxy" in res.stdout
        except Exception:
            return False
    else:
        home = Path.home()
        user_service = home / ".config" / "systemd" / "user" / "vpn-spoof.service"
        autostart_desktop = home / ".config" / "autostart" / "vpn-spoof.desktop"
        system_service = Path("/etc/systemd/system/vpn-spoof.service")
        return user_service.exists() or autostart_desktop.exists() or system_service.exists()

def render_dashboard(config_store: ConfigStore):
    cfg = config_store.load()
    target_url = cfg.get("target_url")
    headers = cfg.get("headers", {})
    port = cfg.get("listen_port", 54321)
    local_ip = get_best_local_ip()
    service_ok = is_service_installed()

    # Верхний блок сетевого статуса и автозапуска
    status_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    status_table.add_column("Key", style="bold", width=22)
    status_table.add_column("Tag", width=8)
    status_table.add_column("Value")

    if service_ok:
        status_table.add_row("Служба автозапуска", "[bold green][OK][/bold green]", "[green]Установлена (запуск при старте ПК)[/green]")
    else:
        status_table.add_row("Служба автозапуска", "[dim white][--][/dim white]", "[dim]Не установлена (пункт [2] в меню)[/dim]")

    status_table.add_row("Локальный адрес", "[bold cyan][IP][/bold cyan]", f"{local_ip}")
    status_table.add_row("Адрес прокси на ПК", "[bold cyan][URL][/bold cyan]", f"http://127.0.0.1:{port}/sub")

    # Древовидное отображение полученной информации (JSON-структура)
    tree = Tree("[bold cyan]Конфигурация прокси (JSON-дерево)[/bold cyan]")

    # 1. URL подписки (полная строка, без обрезки)
    if target_url:
        url_node = tree.add("[bold]Ссылка подписки (target_url)[/bold]")
        url_node.add(Text(target_url, style="green", overflow="fold"))
    else:
        tree.add("[bold red]Ссылка подписки (target_url):[/bold red] [dim red]Не задана (пункт [1] в меню)[/dim red]")

    # 2. Заголовки клиента / ядра (полные строки без обрезки)
    if headers:
        hdr_node = tree.add(f"[bold green]Заголовки клиента (VLESS / ядра)[/bold green] [dim]({len(headers)} параметров)[/dim]")
        for k, v in headers.items():
            t = Text(overflow="fold")
            t.append(f"{k}: ", style="bold cyan")
            t.append(str(v), style="bright_white")
            hdr_node.add(t)
    else:
        tree.add("[bold red]Заголовки клиента (VLESS / ядра):[/bold red] [dim red]Не перехвачены (пункт [1] в меню)[/dim red]")

    # 3. Дополнительные параметры конфигурации (если есть)
    for k, v in cfg.items():
        if k not in ("target_url", "headers", "listen_port"):
            t = Text(overflow="fold")
            t.append(f"{k}: ", style="bold magenta")
            t.append(str(v), style="white")
            tree.add(t)

    content = Table.grid(padding=(1, 0))
    content.add_row(status_table)
    content.add_row(tree)

    panel = Panel(
        content,
        title="[bold]VPN SPOOF CONFIGURATION MANAGER[/bold]",
        border_style="bright_blue",
        box=box.ASCII
    )
    console.print(panel)

def show_menu():
    menu = (
        " [1] Настройка с телефона (единый QR-код: ссылка + сертификат + клиент)\n"
        " [2] Управление службой автозапуска (установка, статус, удаление)\n"
        " [3] Проверить работу прокси в консоли\n"
        " [4] Перенос конфигурации (экспорт / импорт / файл config.json)\n"
        " [bold red]\\[r][/bold red] Сбросить настройки\n"
        " [bold yellow]\\[q][/bold yellow] Выход"
    )
    console.print(Panel(menu, title="[bold]Меню действий[/bold]", border_style="bright_blue", box=box.ASCII))

def install_service_action():
    clear_screen()
    repo_dir = Path(__file__).absolute().parent.parent.parent
    console.print("[bold cyan]Установка фоновой службы автозапуска...[/bold cyan]\n")

    if sys.platform == "win32":
        ps_script = repo_dir / "src" / "scripts" / "windows" / "install_service.ps1"
        os.system(f'powershell -ExecutionPolicy Bypass -File "{ps_script}"')
    else:
        sh_script = repo_dir / "src" / "scripts" / "linux" / "install_service.sh"
        os.system(f'bash "{sh_script}"')

    wait_key()

def status_service_action():
    clear_screen()
    repo_dir = Path(__file__).absolute().parent.parent.parent
    console.print("[bold cyan]Проверка статуса службы...[/bold cyan]\n")

    if sys.platform == "win32":
        ps_script = repo_dir / "src" / "scripts" / "windows" / "status_service.ps1"
        os.system(f'powershell -ExecutionPolicy Bypass -File "{ps_script}"')
    else:
        sh_script = repo_dir / "src" / "scripts" / "linux" / "status_service.sh"
        os.system(f'bash "{sh_script}"')

    wait_key()

def uninstall_service_action():
    clear_screen()
    repo_dir = Path(__file__).absolute().parent.parent.parent
    console.print("[bold yellow]Удаление фоновой службы...[/bold yellow]\n")

    if sys.platform == "win32":
        ps_script = repo_dir / "src" / "scripts" / "windows" / "uninstall_service.ps1"
        os.system(f'powershell -ExecutionPolicy Bypass -File "{ps_script}"')
    else:
        sh_script = repo_dir / "src" / "scripts" / "linux" / "uninstall_service.sh"
        os.system(f'bash "{sh_script}"')

    wait_key()

def service_menu():
    while True:
        clear_screen()
        installed = is_service_installed()
        status_text = "[bold green]Установлена[/bold green]" if installed else "[dim yellow]Не установлена[/dim yellow]"

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("Key", style="bold", width=22)
        table.add_column("Tag", width=8)
        table.add_column("Value")
        table.add_row("Автозапуск системы", "[bold cyan][SVC][/bold cyan]", status_text)

        panel = Panel(
            table,
            title="[bold]УПРАВЛЕНИЕ СЛУЖБОЙ АВТОЗАПУСКА[/bold]",
            border_style="bright_blue",
            box=box.ASCII
        )
        console.print(panel)

        menu_text = (
            " [1] Установить в автозагрузку (запуск при старте системы)\n"
            " [2] Проверить статус службы и процесса\n"
            " [3] Удалить из автозагрузки (остановить фоновую службу)\n"
            " [bold yellow]\\[q][/bold yellow] Назад в главное меню"
        )
        console.print(Panel(menu_text, title="[bold]Действия со службой[/bold]", border_style="bright_blue", box=box.ASCII))

        console.print("\nВыберите пункт > ", end="", highlight=False)
        sys.stdout.flush()
        try:
            choice = get_key()
            console.print(choice)
        except (KeyboardInterrupt, EOFError):
            break

        if choice in ["q", "0"]:
            break
        elif choice == "1":
            install_service_action()
        elif choice == "2":
            status_service_action()
        elif choice == "3":
            uninstall_service_action()

def bundle_action():
    transfer = BundleTransfer()
    while True:
        clear_screen()
        info = (
            "[bold cyan]СОВЕТ ПО БЫСТРОМУ ПЕРЕНОСУ НА ДРУГОЙ ПК:[/bold cyan]\n"
            "Чтобы перенести все настройки, достаточно просто скопировать файл:\n"
            "  [bold green]data/config.json[/bold green]\n"
            "в ту же папку репозитория на новом компьютере. Это полностью переносит\n"
            "ссылку подписки и все перехваченные заголовки клиента (VLESS / ядра) без повторной настройки!"
        )
        console.print(Panel(info, title="[bold]Файловый перенос[/bold]", border_style="green", box=box.ASCII))

        menu_text = (
            " [1] Экспортировать текущую конфигурацию (QR-код и строка)\n"
            " [2] Импортировать строку бандла (vpnbundle://...)\n"
            " [bold yellow]\\[q][/bold yellow] Назад в главное меню"
        )
        console.print(Panel(menu_text, title="[bold]Перенос через строку/QR[/bold]", border_style="bright_blue", box=box.ASCII))

        console.print("\nВыберите пункт > ", end="", highlight=False)
        sys.stdout.flush()
        try:
            choice = get_key()
            console.print(choice)
        except (KeyboardInterrupt, EOFError):
            break

        if choice in ["q", "0"]:
            break
        elif choice == "1":
            clear_screen()
            try:
                transfer.print_export_qr()
            except Exception as e:
                console.print(f"[bold red]Ошибка экспорта:[/bold red] {e}")
            wait_key()
        elif choice == "2":
            clear_screen()
            b_str = input("Вставьте строку бандла (vpnbundle://...): ").strip()
            if b_str:
                try:
                    transfer.import_bundle_string(b_str)
                    console.print("\n[bold green][OK] Конфигурация успешно импортирована![/bold green]")
                except Exception as e:
                    console.print(f"\n[bold red][FAIL] Ошибка импорта:[/bold red] {e}")
            wait_key()

def interactive_loop():
    config_store = ConfigStore()
    while True:
        clear_screen()
        render_dashboard(config_store)
        show_menu()

        console.print("\nВыберите пункт > ", end="", highlight=False)
        sys.stdout.flush()
        try:
            choice = get_key()
            console.print(choice)
        except (KeyboardInterrupt, EOFError):
            console.print("\nЗавершение работы.")
            break

        if choice in ["q", "0"]:
            console.print("\nЗавершение работы.")
            break

        elif choice == "1":
            clear_screen()
            server = UnifiedSetupServer()
            server.run()

        elif choice == "2":
            service_menu()

        elif choice == "3":
            clear_screen()
            cfg = config_store.load()
            if not cfg.get("target_url") or not cfg.get("headers"):
                console.print("[bold red][!] Сначала настройте ссылку и заголовки (пункт 1) или скопируйте data/config.json![/bold red]")
                wait_key("\nНажмите любую клавишу для возврата...")
                continue
            console.print("[bold green]Запуск Spoof Proxy в консоли...[/bold green]")
            proxy = SpoofProxyServer()
            proxy.run()

        elif choice == "4":
            bundle_action()

        elif choice == "r":
            console.print("\nСбросить конфигурацию? ([bold red]y[/bold red]/[bold green]N[/bold green]): ", end="", highlight=False)
            sys.stdout.flush()
            try:
                confirm = get_key()
                console.print(confirm)
            except (KeyboardInterrupt, EOFError):
                continue
            if confirm == "y":
                config_store.save({})
                console.print("[bold yellow]Конфигурация сброшена.[/bold yellow]")
                time.sleep(1)

def main():
    try:
        if len(sys.argv) > 1:
            import argparse
            parser = argparse.ArgumentParser(description="VPN Spoof CLI")
            subparsers = parser.add_subparsers(dest="command")
            subparsers.add_parser("setup", help="Run unified phone setup server")
            subparsers.add_parser("proxy", help="Run proxy daemon")
            subparsers.add_parser("export", help="Export bundle")
            import_p = subparsers.add_parser("import", help="Import bundle")
            import_p.add_argument("bundle", nargs="?")
            subparsers.add_parser("install", help="Install background service")
            subparsers.add_parser("status", help="Check background service status")
            subparsers.add_parser("uninstall", help="Uninstall background service")

            args = parser.parse_args()
            if args.command == "setup":
                UnifiedSetupServer().run()
            elif args.command == "proxy":
                SpoofProxyServer().run()
            elif args.command == "export":
                BundleTransfer().print_export_qr()
            elif args.command == "import":
                b = args.bundle or input("Bundle: ").strip()
                BundleTransfer().import_bundle_string(b)
            elif args.command == "install":
                install_service_action()
            elif args.command == "status":
                status_service_action()
            elif args.command == "uninstall":
                uninstall_service_action()
            else:
                interactive_loop()
        else:
            interactive_loop()
    except KeyboardInterrupt:
        console.print("\nЗавершение работы.")
        sys.exit(0)

if __name__ == "__main__":
    main()

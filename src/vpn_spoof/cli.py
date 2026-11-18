import sys
import os
import time
import subprocess
import json
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
from .dpi_check import (
    check_dns_hijack,
    detect_physical_source_ip,
    load_targets_from_store,
    parse_socks5_proxy,
    run_batch_diagnostics,
    run_cdn_tcp16_check,
)
from .net_utils import get_best_local_ip

console = Console()

def clear_screen():
    # Fast, flicker-free ANSI screen clear and cursor reset
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

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
        " [5] Проверка ТСПУ / DPI (подписка, DNS, каскад)\n"
        " [bold red]\\[r][/bold red] Сбросить настройки\n"
        " [bold yellow]\\[q][/bold yellow] Выход"
    )
    console.print(Panel(menu, title="[bold]Меню действий[/bold]", border_style="bright_blue", box=box.ASCII))

def run_service_script(script_name: str):
    repo_dir = Path(__file__).absolute().parent.parent.parent
    if sys.platform == "win32":
        ps_script = (repo_dir / "src" / "scripts" / "windows" / f"{script_name}.ps1").resolve()
        # Direct Unicode process invocation bypassing cmd.exe to preserve Cyrillic paths
        cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps_script)]
        subprocess.run(cmd)
    else:
        sh_script = (repo_dir / "src" / "scripts" / "linux" / f"{script_name}.sh").resolve()
        subprocess.run(["bash", str(sh_script)])

def install_service_action():
    clear_screen()
    console.print("[bold cyan]Установка фоновой службы автозапуска...[/bold cyan]\n")
    run_service_script("install_service")
    wait_key()

def status_service_action():
    clear_screen()
    console.print("[bold cyan]Проверка статуса службы...[/bold cyan]\n")
    run_service_script("status_service")
    wait_key()

def uninstall_service_action():
    clear_screen()
    console.print("[bold yellow]Удаление фоновой службы...[/bold yellow]\n")
    run_service_script("uninstall_service")
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
        except EOFError:
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
        except EOFError:
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

def _badge(verdict: str) -> str:
    styles = {
        "CLEAN": "[bold green]OK[/bold green]",
        "FROZEN": "[bold red]BLOCK[/bold red]",
        "BLOCKED": "[bold red]BLOCK[/bold red]",
        "BLOCKED_ALL": "[bold red]BLOCK[/bold red]",
        "WHITELIST_SNI": "[bold red]SNI-WL[/bold red]",
        "SPOOFED": "[bold red]SPOOF[/bold red]",
        "CONN_ERR": "[yellow]ERR[/yellow]",
        "TLS_ERR": "[yellow]TLS[/yellow]",
        "DNS_ERR": "[red]DNS[/red]",
        "PARTIAL": "[yellow]PART[/yellow]",
        "WARN": "[yellow]WARN[/yellow]",
        "INCON": "[yellow]?[/yellow]",
        "SKIPPED": "[dim]-[/dim]",
    }
    return styles.get(verdict, verdict)


def render_dpi_results(results: list[dict], title: str = "Результаты проверки ТСПУ / DPI"):
    table = Table(title=title, box=box.ASCII, show_lines=False)
    table.add_column("Узел / Хост", style="cyan", overflow="fold")
    table.add_column("Порт", justify="right", width=5)
    table.add_column("16-20KB", justify="center", width=7)
    table.add_column("Burst", justify="center", width=7)
    table.add_column("SNI", justify="center", width=7)
    table.add_column("DNS", justify="center", width=7)
    table.add_column("Итог", justify="center", width=7)

    clean_cnt = 0
    for item in results:
        if item.get("verdict") == "CLEAN":
            clean_cnt += 1
        label = item.get("label") or item.get("host", "")
        host = item.get("host", "")
        name_col = f"{label}\n[dim]{host}[/dim]" if label != host else host
        table.add_row(
            name_col,
            str(item.get("port", 443)),
            _badge(item["l4_25"]["v"]),
            _badge(item["siberian"]["v"]),
            _badge(item["sni"]["v"]),
            _badge(item["dns"]["v"]),
            _badge(item["verdict"]),
        )
    console.print(table)
    console.print(f"[bold]Итого доступно без ограничений:[/bold] {clean_cnt}/{len(results)}")


def render_cdn_results(report: dict):
    table = Table(title="Срез TCP 16-20KB по CDN / хостингам", box=box.ASCII, show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("ASN", no_wrap=True)
    table.add_column("Провайдер", overflow="fold")
    table.add_column("Адрес", overflow="fold")
    table.add_column("Статус", justify="center", no_wrap=True)
    table.add_column("Детали", overflow="fold")

    for row in report["rows"]:
        table.add_row(
            row["id"],
            row["asn"],
            row["provider"],
            f"{row['ip']}:{row['port']}",
            _badge(row["status"]),
            row["detail"],
        )
    console.print(table)
    console.print(
        f"[bold]Прошло 16-20KB:[/bold] {report['ok']}/{report['total']}  "
        f"[dim](источник базы: {report['catalog_source']})[/dim]"
    )


def dpi_check_menu(config_store: ConfigStore):
    while True:
        clear_screen()
        phys_ip = detect_physical_source_ip()
        info = (
            f"Физический интерфейс (авто-обход TUN): [bold cyan]{phys_ip or 'по умолчанию'}[/bold cyan]\n"
            f"Кэш внешних списков хранится только в системном кэше вне репозитория."
        )
        console.print(Panel(info, title="[bold]ПРОВЕРКА ТСПУ / DPI[/bold]", border_style="bright_blue", box=box.ASCII))
        menu_text = (
            " [1] Проверить узлы текущей подписки (напрямую, авто-обход TUN)\n"
            " [2] Проверить узлы или сайт через локальный SOCKS5-прокси\n"
            " [3] Срез TCP 16-20KB по CDN + проверка подмены DNS\n"
            " [4] Проверить произвольный хост или домен\n"
            " [bold yellow]\\[q][/bold yellow] Назад в главное меню"
        )
        console.print(Panel(menu_text, title="[bold]Режим диагностики[/bold]", border_style="bright_blue", box=box.ASCII))
        console.print("\nВыберите пункт > ", end="", highlight=False)
        sys.stdout.flush()
        try:
            choice = get_key()
            console.print(choice)
        except EOFError:
            break

        if choice in ["q", "0"]:
            break
        elif choice == "1":
            clear_screen()
            console.print("[bold cyan]Загрузка узлов подписки и параллельная проверка ТСПУ...[/bold cyan]")
            try:
                targets = load_targets_from_store(config_store)
                if not targets:
                    console.print("[yellow]Подписки в data/config.json не настроены.[/yellow]")
                else:
                    results = run_batch_diagnostics(targets, source_ip=phys_ip)
                    render_dpi_results(results, title=f"Узлы подписки (через {phys_ip or 'маршрут по умолчанию'})")
            except Exception as exc:
                console.print(f"[bold red]Ошибка проверки:[/bold red] {exc}")
            wait_key()
        elif choice == "2":
            clear_screen()
            proxy_str = input("SOCKS5-прокси [127.0.0.1:7897]: ").strip() or "127.0.0.1:7897"
            target_str = input("Хост/домен (Enter — узлы из подписки + youtube.com): ").strip()
            try:
                socks_proxy = parse_socks5_proxy(proxy_str)
                targets = [t.strip() for t in target_str.split(",") if t.strip()] if target_str else (
                    load_targets_from_store(config_store) + [{"host": "www.youtube.com", "port": 443, "label": "youtube.com"}]
                )
                console.print(f"[bold cyan]Проверка через {proxy_str}...[/bold cyan]")
                results = run_batch_diagnostics(targets, socks_proxy=socks_proxy)
                render_dpi_results(results, title=f"Через SOCKS5 {proxy_str}")
            except Exception as exc:
                console.print(f"[bold red]Ошибка проверки:[/bold red] {exc}")
            wait_key()
        elif choice == "3":
            clear_screen()
            console.print("[bold cyan]Проверка подмены DNS для youtube.com и среза TCP 16-20KB...[/bold cyan]")
            try:
                dns_res = check_dns_hijack("youtube.com", source_ip=phys_ip)
                console.print(f"DNS youtube.com: {_badge(dns_res['v'])} ({dns_res['d']})")
                for rname, rval, rtag in dns_res["rows"]:
                    console.print(f"  {rname:<12} {rval:<24} {rtag}")
                cdn_rep = run_cdn_tcp16_check(source_ip=phys_ip)
                render_cdn_results(cdn_rep)
            except Exception as exc:
                console.print(f"[bold red]Ошибка проверки:[/bold red] {exc}")
            wait_key()
        elif choice == "4":
            clear_screen()
            raw = input("Введите host, host:port или URL: ").strip()
            if raw:
                console.print(f"[bold cyan]Проверка {raw}...[/bold cyan]")
                results = run_batch_diagnostics([raw], source_ip=phys_ip)
                render_dpi_results(results)
            wait_key()


def run_check_cli(args):
    store = ConfigStore(Path(args.config)) if args.config else ConfigStore()
    socks_proxy = parse_socks5_proxy(args.socks) if args.socks else None
    if socks_proxy is not None:
        source_ip = None
    elif args.source_ip:
        source_ip = args.source_ip
    elif args.no_bypass_tun:
        source_ip = None
    else:
        source_ip = detect_physical_source_ip()

    if args.cdn:
        report = run_cdn_tcp16_check(
            allow_download=not args.no_download,
            source_ip=source_ip,
            socks_proxy=socks_proxy,
            timeout=args.timeout,
            limit=args.limit,
        )
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            render_cdn_results(report)
        return

    targets: list = []
    if args.host:
        for entry in args.host:
            targets.extend([item.strip() for item in entry.split(",") if item.strip()])
    else:
        targets = load_targets_from_store(store, timeout=args.timeout)

    if not targets:
        console.print("[yellow]Нет целей для проверки: передайте --host или настройте config.json.[/yellow]")
        sys.exit(1)

    results = run_batch_diagnostics(
        targets,
        source_ip=source_ip,
        socks_proxy=socks_proxy,
        timeout=args.timeout,
        include_siberian=not args.no_siberian,
    )
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        mode = f"SOCKS5 {args.socks}" if args.socks else (f"IP {source_ip}" if source_ip else "маршрут по умолчанию")
        render_dpi_results(results, title=f"Проверка ТСПУ / DPI ({mode})")


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
        except EOFError:
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

        elif choice == "5":
            dpi_check_menu(config_store)

        elif choice == "r":
            console.print("\nСбросить конфигурацию? ([bold red]y[/bold red]/[bold green]N[/bold green]): ", end="", highlight=False)
            sys.stdout.flush()
            try:
                confirm = get_key()
                console.print(confirm)
            except EOFError:
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
            proxy_p = subparsers.add_parser("proxy", help="Run proxy daemon")
            proxy_p.add_argument("--port", type=int, default=None, help="Переопределить порт прослушивания")
            proxy_p.add_argument("--host", type=str, default="127.0.0.1", help="Переопределить адрес прослушивания")
            proxy_p.add_argument("--config", type=str, default=None, help="Путь к альтернативному config.json")
            check_p = subparsers.add_parser("check", help="Лёгкая проверка ТСПУ / DPI")
            check_p.add_argument("--host", action="append", default=None, help="Хост, host:port или список через запятую")
            check_p.add_argument("--config", type=str, default=None, help="Путь к config.json с подписками")
            check_p.add_argument("--socks", type=str, default=None, help="Проверить через SOCKS5 (напр. 127.0.0.1:7897)")
            check_p.add_argument("--source-ip", type=str, default=None, help="Явный исходящий IPv4 интерфейса")
            check_p.add_argument("--no-bypass-tun", action="store_true", help="Не обходить активный TUN автоматически")
            check_p.add_argument("--cdn", action="store_true", help="Проверить срез TCP 16-20KB по локально кэшированной базе CDN")
            check_p.add_argument("--limit", type=int, default=None, help="Ограничить число целей в --cdn")
            check_p.add_argument("--no-download", action="store_true", help="Не скачивать внешнюю базу tcp16.json")
            check_p.add_argument("--no-siberian", action="store_true", help="Пропустить тест параллельных TLS-сессий")
            check_p.add_argument("--timeout", type=float, default=5.0, help="Таймаут сетевых проверок в секундах")
            check_p.add_argument("--json", action="store_true", help="Вывести результат в JSON")
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
                store = ConfigStore(Path(args.config)) if args.config else None
                SpoofProxyServer(listen_port=args.port, host=args.host, config_store=store).run()
            elif args.command == "check":
                run_check_cli(args)
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

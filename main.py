import argparse
import sys
from BanDNS import BanDNS


def main():
    parser = argparse.ArgumentParser(
        prog="ban_dns",
        description="Локальный DNS-блокировщик"
    )

    subparsers = parser.add_subparsers(dest="command", help="Действия программы")

    serve_parser = subparsers.add_parser("server", help="Запустить DNS-сервер")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Адрес для прослушивания (по умолчанию 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=53, help="Порт для прослушивания (по умолчанию 53)")
    serve_parser.add_argument("--upstream", default="8.8.8.8", help="Вышестоящий DNS сервер (по умолчанию 8.8.8.8)")
    serve_parser.add_argument("--rules", default="domains_list.txt", help="Файл со списком заблокированных доменов (по умолчанию domains_list.txt)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "server":
        print("Инициализация сервера")
        server = BanDNS(rules_file_path=args.rules)

        try:
            server.server(host=args.host, port=args.port, upstream_dns=args.upstream)
            print("Сервер запущен")
        except KeyboardInterrupt:
            print("\n[!] Сервер остановлен пользователем")
        except Exception as e:
            print(f"[X] Критическая ошибка: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
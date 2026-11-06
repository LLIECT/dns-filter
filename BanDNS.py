import socket


class BanDNS():
    def __init__(self, rules_file_path: str):
        self.rules_file_path = rules_file_path
        self.banned_domains = set()
        self.load_file()

    def load_file(self):
        try:
            with open(self.rules_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip().lower()
                    if line:
                        self.banned_domains.add(line)
        except FileNotFoundError:
            print(f"Файл правил '{self.rules_file_path}' не найден.")

    def is_blocked(self, domain: str) -> bool:
        if domain in self.banned_domains:
            return True

        parts = domain.split('.')

        for i in range(1, len(parts)):
            parent_domain = ".".join(parts[i:])
            if parent_domain in self.banned_domains:
                return True
        return False

    def server(self, host: str, port: int, upstream_dns: str) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            sock.bind((host, port))

            while True:
                data, addr = sock.recvfrom(4096)

                domain = self._domain_parser(data)

                if domain is None:
                    continue
                if self.is_blocked(domain):
                    response_bytes = self._build_nxdomain_response(data)
                    sock.sendto(response_bytes, addr)
                else:
                    forwarded_response = self._forwarder(data, upstream_dns)

                    if forwarded_response:
                        sock.sendto(forwarded_response, addr)
                    else:
                        error_response = self._build_nxdomain_response(data)
                        sock.sendto(error_response, addr)
        except KeyboardInterrupt:
            print("Ctrl + C остановка сервера")
        except Exception as e:
            print(f"Фатальная ошибка: {e}")
        finally:
            sock.close()
            print("Сокет закрыт. Работа сервера прекращена")


    def _domain_parser(self, data: bytes) -> str | None:

        if len(data) < 13:
            return None

        index = 12
        labels = []

        while index < len(data):
            byte_len = data[index]

            if byte_len == 0:
                break

            if byte_len > 63:
                return None

            index += 1

            if index + byte_len > len(data):
                return None

            label_bytes = data[index:index + byte_len]
            label_str = label_bytes.decode("ascii", errors="ignore").lower()

            if not label_str:
                return None

            labels.append(label_str)
            index += byte_len

        if not labels:
            return None

        return ".".join(labels)

    def _build_nxdomain_response(self, request_data: bytes) -> bytes:
        response = bytearray(request_data)
        response[2] |= 0x80
        response[3] &= 0xF0
        response[3] |= 0x03
        response[6:12] = b'\x00\x00\x00\x00\x00\x00'
        return bytes(response)

    def _forwarder(self, data: bytes, upstream_dns: str) -> bytes | None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
            upstream_sock.settimeout(2.0)
            try:
                upstream_sock.sendto(data, (upstream_dns, 53))
                response, _ = upstream_sock.recvfrom(4096)
                return response
            except socket.timeout:
                return None
            except Exception as e:
                return None
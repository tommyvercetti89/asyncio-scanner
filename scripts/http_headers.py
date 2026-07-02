"""
Ornek Script: HTTP Guvenlik Basliklari Kontrolu
Port: 80, 443, 8080, 8443
Risk: ORTA
"""
import ssl

NAME = "HTTP Guvenlik Basliklari"
DESCRIPTION = "HTTP yanitinda eksik guvenlik basliklarini kontrol eder"
PORTS = [80, 443, 8080, 8443]
AUTHOR = "AHU Scanner"
RISK = "ORTA"


def check(target: str, port: int, use_ssl: bool = False) -> list:
    import socket

    results = []
    required_headers = {
        "Strict-Transport-Security": "HSTS eksik - MITM riski",
        "X-Content-Type-Options": "MIME sniffing korumasi eksik",
        "X-Frame-Options": "Clickjacking korumasi eksik",
        "Content-Security-Policy": "CSP politikasi tanimlanmamis",
        "X-XSS-Protection": "XSS filtresi eksik (eski tarayicilar)",
        "Referrer-Policy": "Referrer politikasi eksik",
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=target)

        sock.connect((target, port))

        req = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: AHUScanner/4.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.send(req.encode())
        sock.settimeout(2.0)

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except Exception:
                break

        sock.close()

        headers_text = response.decode("utf-8", errors="ignore")
        headers_lower = headers_text.lower()

        for header, description in required_headers.items():
            if header.lower() not in headers_lower:
                results.append(
                    {
                        "ad": f"Eksik: {header}",
                        "sev": "DUSUK",
                        "acik": description,
                        "coz": f"Sunucu yanitina `{header}` basligini ekleyin",
                    }
                )

        if "server:" in headers_lower:
            import re
            m = re.search(r"server:\s*(.+)", headers_lower)
            if m:
                results.append(
                    {
                        "ad": "Server Bilgisi Acikta",
                        "sev": "DUSUK",
                        "acik": f"Sunucu: {m.group(1).strip()}",
                        "coz": "Server header'ini gizleyin (server_tokens off)",
                    }
                )

    except Exception:
        pass

    return results

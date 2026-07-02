"""
Ornek Script: SMB Bilgi Toplama
Port: 445
Risk: ORTA
"""
import socket
import struct
import re

NAME = "SMB Bilgi Toplama"
DESCRIPTION = "SMB sunucusundan surum ve yapilandirma bilgisi toplar"
PORTS = [445]
AUTHOR = "AHU Scanner"
RISK = "ORTA"


def _netbios_session_request(target: str, port: int, timeout: float = 3.0) -> bytes:
    """NetBIOS oturum istegi"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    nb_name = b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00"
    nb_request = (
        b"\x81\x00\x00\x44\x20"
        + nb_name
        + b"\x00\x20\x46\x44\x45\x46\x44\x45\x46\x44\x45\x46\x44\x45\x46\x00"
        + b"\x00\x20\x46\x44\x45\x46\x44\x45\x46\x44\x45\x46\x44\x45\x46\x41\x41\x00"
    )

    sock.connect((target, port))
    sock.send(nb_request)
    sock.settimeout(timeout)

    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass

    sock.close()
    return data


def check(target: str, port: int, use_ssl: bool = False) -> list:
    results = []

    try:
        nb_response = _netbios_session_request(target, port)
        if nb_response:
            response_text = nb_response.decode("utf-8", errors="ignore").replace("\x00", "")
            results.append(
                {
                    "ad": "SMB NetBIOS Yaniti Alindi",
                    "sev": "DUSUK",
                    "acik": f"SMB sunucusu NetBIOS isteklerine yanit veriyor: {response_text[:200]}",
                    "coz": "NetBIOS over TCP/IP'yi devre disi birakin (port 139 dahil)",
                }
            )
    except Exception:
        pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((target, port))

        # SMB negotiate protocol request
        smb_negotiate = (
            b"\x00\x00\x00\xa4\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc0"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
            b"\x00\x00\x00\x00\x00\x6d\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f"
            b"\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02"
            b"\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f"
            b"\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70"
            b"\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30"
            b"\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54"
            b"\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
        )

        sock.send(smb_negotiate)
        sock.settimeout(2.0)

        data = b""
        try:
            data = sock.recv(4096)
        except Exception:
            pass

        sock.close()

        if data and len(data) > 40:
            dialect_index = data[36]
            smb_data = data[37:]
            results.append(
                {
                    "ad": "SMB Protokol Yaniti Alindi",
                    "sev": "DUSUK",
                    "acik": f"SMB diyalekt indeksi: {dialect_index}",
                    "coz": "SMBv1 destegi varsa devre disi birakin",
                }
            )
    except Exception:
        pass

    return results

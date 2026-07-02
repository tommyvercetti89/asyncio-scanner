# AHU - Advanced Port Scanner v4.0

Gelişmiş asenkron port tarayıcı. TCP/UDP tarama, SSL banner grabbing, SYN scan, OS tespiti, zafiyet veritabanı ve NSE benzeri script motoru.

## Özellikler

- **Asenkron TCP Tarama** — `asyncio` + `ThreadPoolExecutor` ile yüksek eşzamanlı bağlantı
- **UDP Tarama** — Protokole özel payload'lar (DNS, NTP, SNMP, SSDP)
- **SYN Half-Open Tarama** — Scapy ile gizli tarama (admin yetkisi gerektirir)
- **SSL/TLS Banner Grabbing** — HTTPS servislerinden banner toplama
- **OS Tespiti** — TTL + banner + port kombinasyonu ile işletim sistemi tahmini
- **Zafiyet Veritabanı** — Harici JSON dosyasından yüklenen 27+ port için CVE veritabanı
- **Script Motoru** — NSE benzeri, `scripts/` klasöründen otomatik yüklenen eklenti sistemi
- **Host Discovery** — ICMP + TCP ping ile canlı host keşfi
- **CIDR/Ağ Taraması** — `192.168.1.0/24`, IP aralıkları, liste desteği
- **Çoklu Export** — JSON, CSV, TXT, HTML, Nmap XML formatları
- **Platform Desteği** — Windows, Linux, macOS

## Kurulum

```bash
git clone https://github.com/tommyvercetti89/ahu-scanner.git
cd ahu-scanner
```

### Gereksinimler

```bash
# Temel (tüm özellikler için)
pip install colorama

# SYN Scan için
pip install scapy
```

## Kullanım

```bash
python asscane.py
```

Menü:
```
[ ANA MENU ]
  1. Hizli Tarama (Yaygin portlar)
  2. Ozel Port Araligi Tarama
  3. Tum Portlari Tara (1-65535)
  4. Servis Tespiti (Banner Grabbing)
  5. UDP Port Tarama
  6. SYN Half-Open Tarama
  7. Ag / CIDR Tarama
  8. Host Discovery (Ping Sweep)
  9. Gelismis Ayarlar
  0. Cikis
```

## Script Motoru

`scripts/` klasörüne yeni `.py` dosyaları ekleyerek tarayıcıyı genişletebilirsiniz.

Örnek script yapısı:
```python
NAME = "Script Adi"
DESCRIPTION = "Aciklama"
PORTS = [80, 443]
AUTHOR = "Isim"
RISK = "ORTA"

def check(target: str, port: int, use_ssl: bool = False) -> list:
    results = []
    # ... kontrol mantığı ...
    return results
```

## Zafiyet Veritabanı

`vuln_db.json` dosyasını düzenleyerek yeni zafiyetler ekleyebilirsiniz. Yapı:

```json
{
  "vulnerabilities": {
    "PORT": [
      {
        "ad": "Zafiyet Adi",
        "sev": "KRITIK|YUKSEK|ORTA|DUSUK",
        "cve": "CVE-XXXX-XXXXX",
        "acik": "Aciklama",
        "coz": "Cozum onerisi"
      }
    ]
  },
  "banner_checks": [...]
}
```

## Sorumluluk Reddi

Bu araç yalnızca **yetkili güvenlik testleri** için geliştirilmiştir. İzinsiz ağ taraması yasa dışıdır. Kullanıcı tüm hukuki sorumluluğu kabul eder.

## Lisans

MIT License - detaylar için [LICENSE](LICENSE) dosyasına bakın.

#!/usr/bin/env python3
"""
Gelismis Asenkron Port Tarayici v4.0
Asyncio + SSL Banner + SYN Scan + Nmap XML + Script Motoru + Zafiyet DB
Windows / Linux / Mac uyumlu
"""

import asyncio, socket, sys, time, ipaddress, json, csv, os, re, ssl
import concurrent.futures, signal, subprocess, pathlib, importlib.util, xml.etree.ElementTree as ET
from typing import List, Tuple, Optional, Dict, Any, Callable
from datetime import datetime

# ── Windows UTF-8 konsol ──────────────────────────────────────────────────────
if sys.platform == 'win32':
    os.system('chcp 65001 > nul 2>&1')
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ── Colorama (opsiyonel) ──────────────────────────────────────────────────────
try:
    from colorama import init as _ci, Fore as _F, Style as _S
    _ci(autoreset=True, convert=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False
    class _F:
        GREEN=YELLOW=RED=CYAN=MAGENTA=BLUE=WHITE=RESET=''
        LIGHTGREEN_EX=LIGHTYELLOW_EX=LIGHTRED_EX=LIGHTCYAN_EX=''
        LIGHTBLUE_EX=LIGHTWHITE_EX=LIGHTMAGENTA_EX=''
    class _S:
        BRIGHT=DIM=RESET_ALL=''

def _c(text: str, color: str = '', bright: bool = False) -> str:
    if not _HAS_COLOR:
        return text
    return f"{(_S.BRIGHT if bright else '')}{color}{text}{_S.RESET_ALL}"

# ── Tarama Profilleri ─────────────────────────────────────────────────────────
PROFILLER = {
    '1': {'ad':'Gizli',        'timeout':3.0, 'concurrent':50},
    '2': {'ad':'Normal',       'timeout':1.0, 'concurrent':500},
    '3': {'ad':'Agresif',      'timeout':0.3, 'concurrent':1000},
    '4': {'ad':'Ultra Hizli',  'timeout':0.2, 'concurrent':2000},
    '5': {'ad':'Banner Odakli','timeout':2.0, 'concurrent':100},
}

# ── Servis Isimleri ───────────────────────────────────────────────────────────
SERVISLER: Dict[int,str] = {
    21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',67:'DHCP',
    69:'TFTP',80:'HTTP',110:'POP3',111:'RPC',123:'NTP',135:'RPC',
    137:'NetBIOS-NS',138:'NetBIOS-DGM',139:'NetBIOS',143:'IMAP',
    161:'SNMP',162:'SNMP-Trap',389:'LDAP',443:'HTTPS',445:'SMB',
    465:'SMTPS',514:'Syslog',587:'SMTP-TLS',636:'LDAPS',993:'IMAPS',
    995:'POP3S',1433:'MSSQL',1521:'Oracle',1723:'PPTP',2049:'NFS',
    2375:'Docker-API',3000:'HTTP-Dev',3306:'MySQL',3389:'RDP',
    5000:'HTTP-Dev',5432:'PostgreSQL',5601:'Kibana',5900:'VNC',
    6379:'Redis',8000:'HTTP-Alt',8080:'HTTP-Proxy',8443:'HTTPS-Alt',
    8888:'HTTP-Alt',9000:'HTTP-Dev',9090:'Web-Proxy',
    9200:'Elasticsearch',11211:'Memcached',27017:'MongoDB',
}

# ── Zafiyet Veritabani ────────────────────────────────────────────────────────
VULN_DB: Dict[int, List[Dict]] = {
    21:[
        {'ad':'FTP Sifresiz Iletisim','sev':'ORTA',
         'acik':'Tum trafik sifrelenmez, kimlik bilgileri ele gecirilir',
         'coz':'SFTP veya FTPS kullanin'},
        {'ad':'FTP Anonim Erisim','sev':'ORTA',
         'acik':'Anonim giris aktif olabilir',
         'coz':'Anonim FTP erisimini kapatin'},
    ],
    22:[{'ad':'SSH Kaba Kuvvet Riski','sev':'ORTA',
         'acik':'Parola tabanli SSH saldirisindan etkilenebilir',
         'coz':'Anahtar dogrulama kullanin, fail2ban kurun'}],
    23:[{'ad':'Telnet Sifresiz Protokol','sev':'YUKSEK',
         'acik':'Tum trafik duz metin - sifre ve veriler acikta',
         'coz':'SSH kullanin, Telnet portunu kapatin'}],
    25:[{'ad':'SMTP Acik Role','sev':'ORTA',
         'acik':'Acik relay spam icin kullanilabilir',
         'coz':'Relay kisitlayin, kimlik dogrulama zorunlu yapin'}],
    53:[{'ad':'DNS Amplifikasyon Riski','sev':'ORTA',
         'acik':'DDoS amplifikasyon saldirisi icin kullanilabilir',
         'coz':'Recursive DNS kisitlayin, rate limit ekleyin'},
        {'ad':'DNS Zone Transfer','sev':'ORTA',
         'acik':'Zone transfer tum DNS kayitlarini ifsa edebilir',
         'coz':'Zone transferi sadece yetkili NS lere kisitlayin'}],
    80:[{'ad':'HTTP Sifresiz Baglanti','sev':'DUSUK',
         'acik':'Trafik sifrelenmez, MITM ile izlenebilir',
         'coz':'HTTPS ye yonlendirin, HSTS etkinlestirin'}],
    110:[{'ad':'POP3 Sifresiz','sev':'ORTA',
          'acik':'E-posta ve kimlik bilgileri sifrelenmez',
          'coz':'POP3S (995) kullanin'}],
    139:[{'ad':'NetBIOS Bilgi Sizintisi','sev':'ORTA',
          'acik':'Sistem adi ve calisma grubu bilgisi aciga cikabilir',
          'coz':'NetBIOS u devre disi birakin veya guvenlik duvari ekleyin'}],
    143:[{'ad':'IMAP Sifresiz','sev':'ORTA',
          'acik':'E-posta icerigi sifrelenmez',
          'coz':'IMAPS (993) kullanin'}],
    161:[{'ad':'SNMP Public Community','sev':'YUKSEK',
          'acik':'Varsayilan "public" string sistem bilgisini acar',
          'coz':'SNMPv3 kullanin, community string degistirin'}],
    389:[{'ad':'LDAP Sifresiz','sev':'ORTA',
          'acik':'LDAP trafikle kimlik bilgileri sifrelenmez',
          'coz':'LDAPS (636) kullanin'}],
    443:[{'ad':'HTTPS Eski TLS','sev':'DUSUK',
          'acik':'TLS 1.0/1.1 aktif olabilir',
          'coz':'Yalnizca TLS 1.2+ kullanin'}],
    445:[
        {'ad':'EternalBlue','sev':'KRITIK','cve':'CVE-2017-0144',
         'acik':'SMBv1 uzaktan kod yurutme - WannaCry vektoru',
         'coz':'MS17-010 yamasini uygulayin, SMBv1 kapatin'},
        {'ad':'SMBGhost','sev':'KRITIK','cve':'CVE-2020-0796',
         'acik':'SMBv3.1.1 arabelle tasimasi (Win10/Server2019)',
         'coz':'KB4551762 yamasini uygulayin'},
        {'ad':'PrintNightmare','sev':'KRITIK','cve':'CVE-2021-34527',
         'acik':'Print Spooler uzaktan kod yurutme',
         'coz':'MS21-034527 yamasi + Print Spooler devre disi'},
    ],
    1433:[{'ad':'MSSQL Acik Veritabani','sev':'YUKSEK',
           'acik':'Veritabani internete acik, brute force riski',
           'coz':'Guvenlik duvariyla kisitlayin, SA hesabini kapatin'}],
    1521:[{'ad':'Oracle DB Acik Erisim','sev':'YUKSEK',
           'acik':'Oracle brute force ve veri sizintisi riski',
           'coz':'Guvenlik duvariyla kisitlayin'}],
    2375:[{'ad':'Docker API Kimlik Dogrulamasiz','sev':'KRITIK',
           'acik':'Kimlik dogrulamasiz Docker API - tam sistem erisimi',
           'coz':'TLS etkinlestirin veya yalnizca localhost a baglayin'}],
    2049:[{'ad':'NFS Yetkisiz Montaj','sev':'YUKSEK',
           'acik':'NFS dizinleri yetkisiz kullanicilara acik olabilir',
           'coz':'NFS ihraclarini kisitlayin'}],
    3306:[{'ad':'MySQL Acik Erisim','sev':'YUKSEK',
           'acik':'MySQL internete acik, brute force riski',
           'coz':'Guvenlik duvariyla kisitlayin, root uzak girisi kapatin'}],
    3389:[
        {'ad':'BlueKeep','sev':'KRITIK','cve':'CVE-2019-0708',
         'acik':'RDP uzaktan kod yurutme (Win7/Server2008)',
         'coz':'Windows guncelleyin, NLA etkinlestirin'},
        {'ad':'DejaBlue','sev':'KRITIK','cve':'CVE-2019-1181',
         'acik':'RDP uzaktan kod yurutme (Win10/Server2019)',
         'coz':'KB4512508 yamasini uygulayin'},
        {'ad':'RDP Brute Force & Acik Erisim','sev':'YUKSEK',
         'acik':'RDP internete acik, kaba kuvvet saldirisindan etkilenebilir',
         'coz':'VPN arkasina alin, NLA + MFA etkinlestirin'},
    ],
    5432:[{'ad':'PostgreSQL Acik Erisim','sev':'YUKSEK',
           'acik':'Veritabani internete acik',
           'coz':'Yalnizca uygulama sunucusuna izin verin'}],
    5601:[{'ad':'Kibana Kimlik Dogrulamasiz','sev':'YUKSEK',
           'acik':'Kibana arayuzu acikta, tum loglara erisim',
           'coz':'Nginx proxy + kimlik dogrulama ekleyin'}],
    5900:[{'ad':'VNC Zayif Kimlik Dogrulama','sev':'YUKSEK',
           'acik':'VNC genellikle zayif kimlik dogrulama kullanir',
           'coz':'VPN arkasina alin, guclu parola + TLS kullanin'}],
    6379:[
        {'ad':'Redis Kimlik Dogrulamasiz','sev':'KRITIK',
         'acik':'Redis varsayilan olarak kimlik dogrulama istemez',
         'coz':'requirepass ayarlayin, bind 127.0.0.1 kullanin'},
        {'ad':'Redis Lua RCE','sev':'KRITIK','cve':'CVE-2022-0543',
         'acik':'Lua sandbox atlatmayla uzaktan kod yurutme',
         'coz':'Redis >= 6.2.6 surumune guncelleyin'},
    ],
    8080:[{'ad':'HTTP Proxy/Yonetim Acik','sev':'ORTA',
           'acik':'Acik proxy veya yonetim arayuzu olabilir',
           'coz':'Guvenlik duvariyla kisitlayin'}],
    9200:[{'ad':'Elasticsearch Acik Erisim','sev':'KRITIK',
           'acik':'Kimlik dogrulamasiz tum verilere erisim',
           'coz':'X-Pack guvenligini etkinlestirin, IP kisitlayin'}],
    11211:[{'ad':'Memcached DDoS Amplifikasyon','sev':'KRITIK',
            'acik':'UDP Memcached DDoS saldirisi (51000x amplifikasyon)',
            'coz':'UDP yi devre disi birakin, guvenlik duvari ekleyin'}],
    27017:[{'ad':'MongoDB Kimlik Dogrulamasiz','sev':'KRITIK',
            'acik':'MongoDB kimlik dogrulama olmadan calisabilir',
            'coz':'Kimlik dogrulamayi etkinlestirin, bind IP kisitlayin'}],
}

SEV_RENK = {
    'KRITIK': (_F.RED,    True),
    'YUKSEK': (_F.LIGHTRED_EX, False),
    'ORTA':   (_F.YELLOW, False),
    'DUSUK':  (_F.CYAN,   False),
}

_BANNER_CHECKS: List[Dict] = []

def _vuln_db_yukle() -> Dict[int, List[Dict]]:
    """Zafiyet veritabanini vuln_db.json dosyasindan yukler, yoksa statik DB kullanir"""
    global _BANNER_CHECKS
    json_path = pathlib.Path(__file__).parent / 'vuln_db.json'
    if json_path.is_file():
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            vulns = data.get('vulnerabilities', {})
            _BANNER_CHECKS = data.get('banner_checks', [])
            db: Dict[int, List[Dict]] = {}
            for k, v in vulns.items():
                db[int(k)] = v
            if db:
                return db
        except Exception:
            pass
    _BANNER_CHECKS = []
    return VULN_DB

def _vuln_db_al() -> Dict[int, List[Dict]]:
    if not hasattr(_vuln_db_al, '_cache'):
        _vuln_db_al._cache = _vuln_db_yukle()
    return _vuln_db_al._cache

# ── Ana Sinif ─────────────────────────────────────────────────────────────────
class AdvancedPortScanner:
    def __init__(self):
        self.open_ports: List[int] = []
        self.filtered_ports: List[int] = []
        self.udp_open_ports: List[int] = []
        self.banners: Dict[int,str] = {}
        self.udp_banners: Dict[int,str] = {}
        self.semaphore = None
        self.executor = None
        self.scan_start_time = None
        self.timeout = 1.0
        self.max_concurrent = 500
        self.grab_banner = False
        self.last_progress = ''
        self.os_result: Optional[Dict] = None
        self.scan_mode: str = 'tcp'
        self.syn_scan: bool = False
        self.script_results: Dict[int, List[Dict]] = {}
        self._scripts: List[Dict] = []
        self._script_modullerini_yukle()

    # ── Ekran / Banner ────────────────────────────────────────────────────────
    @staticmethod
    def temizle():
        os.system('cls' if os.name == 'nt' else 'clear')

    def banner_yazdir(self):
        sep = _c('=' * 62, _F.BLUE, True)
        print(sep)
        print(_c('     GELISMIS ASENKRON PORT TARAYICI  v4.0', _F.CYAN, True))
        print(_c('     Asyncio + SSL + SYN Scan + Script Motoru + XML', _F.WHITE))
        print(_c('     Windows / Linux / Mac Uyumlu', _F.WHITE))
        print(sep)

    def menu_goster(self):
        while True:
            self.temizle()
            self.banner_yazdir()
            print(_c('\n[ ANA MENU ]', _F.BLUE, True))
            print(_c('-' * 35, _F.BLUE))
            girdi = [
                ('1','Hizli Tarama (Yaygin portlar)',''),
                ('2','Ozel Port Araligi Tarama',''),
                ('3','Tum Portlari Tara (1-65535)',''),
                ('4','Servis Tespiti (Banner Grabbing)',''),
                ('5','UDP Port Tarama',_c(' [YENI]',_F.GREEN,True)),
                ('6','SYN Half-Open Tarama',_c(' [YENI]',_F.GREEN,True)),
                ('7','Ag / CIDR Tarama',''),
                ('8','Host Discovery (Ping Sweep)',''),
                ('9','Gelismis Ayarlar',''),
                ('0','Cikis',''),
            ]
            for n, lbl, badge in girdi:
                print(f"  {_c(n+'.', _F.YELLOW, True)} {lbl}{badge}")
            print(_c('-' * 35, _F.BLUE))
            sec = input(_c('\nSeciminiz (0-9): ', _F.CYAN)).strip()
            eylemler = {'1':self.hizli_tarama,'2':self.ozel_aralik,'3':self.tam_tarama,
                        '4':self.banner_tarama,'5':self.udp_tarama_menu,
                        '6':self.syn_tarama_menu,'7':self.ag_cidr_tarama,
                        '8':self.host_discovery_menu,'9':self.gelismis_ayarlar}
            if sec == '0':
                print(_c('\nProgram kapatiliyor...\n', _F.YELLOW))
                sys.exit(0)
            elif sec in eylemler:
                eylemler[sec]()
            else:
                print(_c('[HATA] Gecersiz secim!', _F.RED))
                time.sleep(1)

    # ── Giris Metodlari ───────────────────────────────────────────────────────
    def hedef_al(self) -> str:
        while True:
            t = input(_c('\nHedef IP veya hostname: ', _F.CYAN)).strip()
            if not t:
                print(_c('[HATA] Hedef bos birakilamaz!', _F.RED)); continue
            try:
                ipaddress.ip_address(t); return t
            except ValueError:
                try:
                    socket.gethostbyname(t); return t
                except Exception:
                    print(_c('[HATA] Gecersiz IP veya hostname!', _F.RED))

    def port_araligi_al(self) -> Tuple[int,int]:
        while True:
            try:
                s = int(input('  Baslangic (1-65535): '))
                e = int(input('  Bitis     (1-65535): '))
                if 1 <= s <= 65535 and 1 <= e <= 65535 and s <= e:
                    return s, e
                print(_c('[HATA] Gecersiz aralik!', _F.RED))
            except ValueError:
                print(_c('[HATA] Sayisal deger girin!', _F.RED))

    def profil_sec(self):
        print(_c('\nTarama profili (Enter = mevcut ayarlar):', _F.CYAN))
        for k,p in PROFILLER.items():
            print(f"  {_c(k+'.', _F.YELLOW)} {p['ad']:18s}"
                  f" timeout={p['timeout']}s  es-zamanli={p['concurrent']}")
        print(f"  {_c('0.', _F.YELLOW)} Mevcut (timeout={self.timeout}s,"
              f" es-zamanli={self.max_concurrent})")
        sec = input(_c('Profiliniz: ', _F.CYAN)).strip()
        if sec in PROFILLER:
            p = PROFILLER[sec]
            self.timeout = p['timeout']
            self.max_concurrent = p['concurrent']
            print(_c(f'[OK] Profil: {p["ad"]}', _F.GREEN))

    def banner_sor(self) -> bool:
        return input(_c('Banner grabbing? (e/h): ', _F.CYAN)).lower() == 'e'

    def os_sor(self) -> bool:
        return input(_c('OS tespiti yapilsin mi? (e/h): ', _F.CYAN)).lower() == 'e'

    # ── Ilerleme & Cikti ──────────────────────────────────────────────────────
    def _sonuc_yazdir(self, mesaj: str):
        """Progress bar ile cakismadan sonuc yazdir"""
        print(f'\r{" " * 120}', end='', flush=True)
        print(f'\r{mesaj}')
        if self.last_progress:
            print(self.last_progress, end='', flush=True)

    async def progress_reporter(self, toplam: int, tamamlanan: list):
        son_pct = -1
        while len(tamamlanan) < toplam:
            pct = int(len(tamamlanan) / toplam * 100)
            if pct != son_pct:
                dolu = int(30 * pct / 100)
                bar = (_c('█' * dolu, _F.GREEN) +
                       _c('░' * (30 - dolu), _F.WHITE))
                self.last_progress = (
                    f'Ilerleme: |{bar}| '
                    f'{_c(f"%{pct}", _F.YELLOW, True)} '
                    f'({len(tamamlanan)}/{toplam})')
                print(f'\r{self.last_progress}', end='', flush=True)
                son_pct = pct
            await asyncio.sleep(0.1)
        self.last_progress = ''
        print(f'\rIlerleme: |{_c("█"*30, _F.GREEN, True)}|'
              f' {_c("%100", _F.GREEN, True)} ({toplam}/{toplam})    ')

    def _acik_port_yazdir(self, port: int, banner: Optional[str], udp=False):
        svc = SERVISLER.get(port, 'bilinmeyen')
        proto = 'UDP' if udp else 'TCP'
        etiket = _c(f'[ACIK-{proto}]', _F.GREEN, True)
        satir = [f'{etiket} Port {_c(str(port), _F.WHITE, True)} - {_c(svc, _F.CYAN)}']
        if banner:
            parts = banner.split(' | ')
            satir.append(f'  {_c("└─", _F.WHITE)} {_c(parts[0][:110], _F.LIGHTCYAN_EX)}')
            for p in parts[1:3]:
                if p.strip():
                    satir.append(f'     {_c(p.strip()[:100], _F.LIGHTCYAN_EX)}')
        vulns = self.zafiyet_kontrol(port, banner)
        for v in vulns[:2]:
            rk, bold = SEV_RENK.get(v['sev'], (_F.WHITE, False))
            sev_tag = _c(f'[{v["sev"]}]', rk, bold)
            cve = f' {_c(v.get("cve",""), _F.WHITE)}' if v.get('cve') else ''
            satir.append(f'  {_c("!!", _F.RED)} {sev_tag} {v["ad"]}{cve}')
        self._sonuc_yazdir('\n'.join(satir))

    # ── TCP Port Tarama ───────────────────────────────────────────────────────
    def _banner_cek(self, sock, target: str, port: int) -> Optional[str]:
        try:
            if port in (443, 8443, 636, 993, 995, 465):
                return self._ssl_banner_cek(target, port)
            if port in (80, 8080, 8000, 8888, 3000, 5000, 9000):
                req = (f'GET / HTTP/1.1\r\nHost: {target}\r\n'
                       f'User-Agent: PortScanner/4.0\r\nAccept: */*\r\n'
                       f'Connection: close\r\n\r\n')
                sock.send(req.encode())
                time.sleep(0.3)
                return self._http_parse(self._recv_all(sock, 8192))
            elif port in (21,22,25,110,143,587,993,995,3306,5432,6379,27017):
                time.sleep(0.2)
                return sock.recv(1024).decode('utf-8','ignore').strip() or None
            else:
                time.sleep(0.1)
                try:
                    d = sock.recv(1024).decode('utf-8','ignore').strip()
                    return d or None
                except Exception:
                    sock.send(b'HELLO\r\n'); time.sleep(0.1)
                    return sock.recv(1024).decode('utf-8','ignore').strip() or None
        except Exception:
            return None

    def _ssl_banner_cek(self, target: str, port: int) -> Optional[str]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=target) as ssock:
                    ssock.settimeout(self.timeout)
                    if port in (443, 8443):
                        req = (f'HEAD / HTTP/1.1\r\nHost: {target}\r\n'
                               f'User-Agent: PortScanner/4.0\r\n'
                               f'Connection: close\r\n\r\n')
                        ssock.send(req.encode())
                    return self._http_parse(self._recv_all(ssock, 4096))
        except Exception:
            return None

    def _recv_all(self, sock, max_b: int) -> bytes:
        data = b''
        sock.settimeout(1.0)
        while True:
            try:
                c = sock.recv(4096)
                if not c: break
                data += c
                if len(data) >= max_b: break
            except Exception:
                break
        return data

    def _http_parse(self, raw: bytes) -> Optional[str]:
        if not raw: return None
        text = raw.decode('utf-8','ignore')
        keep = []
        for line in text.split('\r\n'):
            if any(h in line for h in ('HTTP/','Server:','X-Powered-By:',
                                        'Content-Type:','Location:','X-AspNet-Version:')):
                keep.append(line.strip())
            if line.strip() == '': break
        return ' | '.join(keep[:5]) if keep else text[:200]

    def tcp_port_test(self, target: str, port: int) -> Tuple[int,bool,Optional[str]]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            r = s.connect_ex((target, port))
            banner = None
            if r == 0 and self.grab_banner:
                banner = self._banner_cek(s, target, port)
            s.close()
            return port, r == 0, banner
        except Exception:
            return port, False, None

    async def port_tara(self, target: str, port: int) -> Tuple[int,str,Optional[str]]:
        async with self.semaphore:
            try:
                loop = asyncio.get_event_loop()
                port, acik, banner = await loop.run_in_executor(
                    self.executor, self.tcp_port_test, target, port)
                return port, ('open' if acik else 'closed'), banner
            except asyncio.TimeoutError:
                return port, 'filtered', None
            except Exception as e:
                return port, 'error', str(e)

    async def tarama_calistir(self, target: str, portlar: List[int]):
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        tamamlanan: List[int] = []
        print(f'\n{_c("Tarama baslatiliyor...", _F.CYAN, True)}')
        print(f'  Hedef      : {_c(target, _F.WHITE, True)}')
        print(f'  Port sayisi: {len(portlar)}')
        print(f'  Es zamanli : {self.max_concurrent}  |  Timeout: {self.timeout}s')
        if self.grab_banner:
            print(f'  Banner     : {_c("AKTIF", _F.GREEN, True)}')
        print()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent) as ex:
            self.executor = ex
            prog = asyncio.create_task(self.progress_reporter(len(portlar), tamamlanan))
            gorevler = [asyncio.create_task(self.port_tara(target, p)) for p in portlar]
            for coro in asyncio.as_completed(gorevler):
                try:
                    r = await coro
                except Exception:
                    continue
                if isinstance(r, Exception): continue
                port, durum, banner = r
                tamamlanan.append(port)
                if durum == 'open':
                    self.open_ports.append(port)
                    if banner: self.banners[port] = banner
                    self._acik_port_yazdir(port, banner)
                elif durum == 'filtered':
                    self.filtered_ports.append(port)
            prog.cancel()
            try: await prog
            except asyncio.CancelledError: pass
            self.executor = None

    # ── UDP Port Tarama ───────────────────────────────────────────────────────
    def _udp_payload(self, port: int) -> bytes:
        payloads = {
            53: b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                b'\x07version\x04bind\x00\x00\x10\x00\x03',
            123: b'\x1b' + b'\x00' * 47,
            161: (b'\x30\x26\x02\x01\x00\x04\x06public'
                  b'\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00'
                  b'\x02\x01\x00\x30\x0b\x30\x09\x06\x05'
                  b'\x2b\x06\x01\x02\x01\x05\x00'),
            1900:(b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
                  b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'),
            69:  b'\x00\x01test.txt\x00octet\x00',
        }
        return payloads.get(port, b'\x00')

    def udp_port_test(self, target: str, port: int) -> Tuple[int,str,Optional[str]]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.sendto(self._udp_payload(port), (target, port))
            try:
                data, _ = s.recvfrom(1024)
                return port, 'open', data.decode('utf-8','ignore').strip() or None
            except socket.timeout:
                return port, 'open|filtered', None
            except ConnectionResetError:
                return port, 'closed', None
        except Exception:
            return port, 'error', None
        finally:
            try: s.close()
            except Exception: pass

    async def udp_port_tara(self, target: str, port: int) -> Tuple[int,str,Optional[str]]:
        async with self.semaphore:
            try:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    self.executor, self.udp_port_test, target, port)
            except Exception as e:
                return port, 'error', str(e)

    async def udp_tarama_calistir(self, target: str, portlar: List[int]):
        maks = min(self.max_concurrent, 200)
        self.semaphore = asyncio.Semaphore(maks)
        tamamlanan: List[int] = []
        print(f'\n{_c("UDP Tarama baslatiliyor...", _F.CYAN, True)}')
        print(f'  Not: UDP sonuclari TCP ye gore belirsiz olabilir.\n')
        with concurrent.futures.ThreadPoolExecutor(max_workers=maks) as ex:
            self.executor = ex
            prog = asyncio.create_task(self.progress_reporter(len(portlar), tamamlanan))
            gorevler = [asyncio.create_task(self.udp_port_tara(target, p)) for p in portlar]
            for coro in asyncio.as_completed(gorevler):
                try: r = await coro
                except Exception: continue
                if isinstance(r, Exception): continue
                port, durum, banner = r
                tamamlanan.append(port)
                if durum == 'open':
                    self.udp_open_ports.append(port)
                    if banner: self.udp_banners[port] = banner
                    self._acik_port_yazdir(port, banner, udp=True)
                elif durum == 'open|filtered' and port in SERVISLER:
                    svc = SERVISLER.get(port,'')
                    msg = (f'{_c("[UDP?]", _F.YELLOW)} Port '
                           f'{_c(str(port), _F.WHITE, True)} - '
                           f'{_c(svc, _F.CYAN)} '
                           f'{_c("(acik|filtrelenmis)", _F.YELLOW)}')
                    self._sonuc_yazdir(msg)
            prog.cancel()
            try: await prog
            except asyncio.CancelledError: pass
            self.executor = None

    # ── OS Tespiti ────────────────────────────────────────────────────────────
    def _ttl_al(self, target: str) -> Optional[int]:
        try:
            cmd = (['ping','-n','1','-w','1500',target] if sys.platform=='win32'
                   else ['ping','-c','1','-W','2',target])
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                          timeout=4, encoding='utf-8', errors='ignore')
            m = re.search(r'ttl=(\d+)', out, re.IGNORECASE)
            return int(m.group(1)) if m else None
        except Exception:
            return None

    def _banner_os_analiz(self, port: int, banner: str,
                          skorlar: Dict[str,float], sinyaller: List[str]):
        b = banner.lower()
        if port == 22:
            if 'openssh' in b:
                for distro, kw in (('Ubuntu','ubuntu'),('Debian','debian'),
                                   ('CentOS','centos'),('RHEL','rhel'),
                                   ('FreeBSD','freebsd')):
                    if kw in b:
                        os_k = 'FreeBSD' if distro=='FreeBSD' else 'Linux'
                        skorlar[os_k] += 35
                        sinyaller.append(f'SSH: OpenSSH ({distro})')
                        return
                skorlar['Linux'] += 22; skorlar['macOS'] += 10
                sinyaller.append('SSH: OpenSSH (Linux/Mac)')
            elif 'dropbear' in b:
                skorlar['Embedded/IoT'] += 35
                sinyaller.append('SSH: Dropbear (Gomulu Sistem/IoT)')
            elif 'cisco' in b:
                skorlar['Cisco/Network'] += 40
                sinyaller.append('SSH: Cisco IOS')
        elif port in (80,8080,8000,443,8443,5000,3000):
            m = re.search(r'microsoft-iis/(\d+)', b, re.IGNORECASE)
            if m:
                ver = int(m.group(1))
                ver_map = {10:'2016/2019/2022', 8:'2012 R2', 7:'2008 R2'}
                skorlar['Windows'] += 40
                sinyaller.append(f'HTTP: IIS/{ver} -> Windows Server {ver_map.get(ver,"")}')
            elif 'apache' in b:
                skorlar['Linux'] += 20
                for d,kw in (('Ubuntu','ubuntu'),('CentOS','centos')):
                    if kw in b:
                        skorlar['Linux'] += 12
                        sinyaller.append(f'HTTP: Apache ({d})'); return
                sinyaller.append('HTTP: Apache (Linux/Unix)')
            elif 'nginx' in b:
                skorlar['Linux'] += 18; sinyaller.append('HTTP: Nginx')
            if 'x-aspnet-version' in b:
                skorlar['Windows'] += 18; sinyaller.append('HTTP: ASP.NET (Windows)')
        elif port == 21:
            if 'vsftpd' in b:   skorlar['Linux'] += 22;    sinyaller.append('FTP: vsftpd (Linux)')
            elif 'filezilla' in b: skorlar['Windows'] += 12; sinyaller.append('FTP: FileZilla (Windows)')
            elif 'microsoft ftp' in b: skorlar['Windows'] += 30; sinyaller.append('FTP: Microsoft FTP')
            elif 'proftpd' in b: skorlar['Linux'] += 18;   sinyaller.append('FTP: ProFTPD')
        elif port in (25,587):
            if 'exchange' in b or 'microsoft' in b:
                skorlar['Windows'] += 28; sinyaller.append('SMTP: Microsoft Exchange')
            elif 'postfix' in b:  skorlar['Linux'] += 22;  sinyaller.append('SMTP: Postfix')
            elif 'exim' in b:     skorlar['Linux'] += 18;  sinyaller.append('SMTP: Exim')

    def _servis_kombo(self, skorlar: Dict[str,float], sinyaller: List[str]):
        op = set(self.open_ports)
        win = {445,3389,135,139}
        win_hit = op & win
        if win_hit:
            skorlar['Windows'] += len(win_hit) * 18
            sinyaller.append(f'Port kombo: {sorted(win_hit)} -> Windows')
        lin = {111,2049}
        lin_hit = op & lin
        if lin_hit and 3389 not in op:
            skorlar['Linux'] += len(lin_hit) * 15
            sinyaller.append(f'Port kombo: {sorted(lin_hit)} -> Linux')
        net = {23,161,162}
        net_hit = op & net
        if net_hit:
            skorlar['Cisco/Network'] += len(net_hit) * 12
            sinyaller.append(f'Port kombo: {sorted(net_hit)} -> Ag Cihazi')

    def _os_versiyon(self, best: str, sinyaller: List[str]) -> str:
        hints = {
            'IIS/10':'Windows Server 2016/2019/2022 veya Windows 10/11',
            'IIS/8' :'Windows Server 2012 R2',
            'IIS/7' :'Windows Server 2008 R2',
            'Ubuntu':'Linux - Ubuntu/Debian tabanli',
            'CentOS':'Linux - CentOS/RHEL tabanli',
            'Dropbear':'Gomulu Linux / OpenWRT',
            'Cisco':'Cisco IOS / IOS-XE',
            'FreeBSD':'FreeBSD',
        }
        for key, val in hints.items():
            if any(key in s for s in sinyaller):
                return val
        return best

    def os_tespit(self, target: str) -> Dict:
        skorlar = {'Windows':0.0,'Linux':0.0,'macOS':0.0,
                   'FreeBSD':0.0,'Cisco/Network':0.0,'Embedded/IoT':0.0}
        sinyaller: List[str] = []

        print(f'  {_c("->", _F.CYAN)} TTL degeri aliniyor... ', end='', flush=True)
        ttl = self._ttl_al(target)
        if ttl:
            print(_c(f'TTL={ttl}', _F.WHITE, True))
            if 50 <= ttl <= 65:
                skorlar['Linux'] += 25; skorlar['macOS'] += 10
                sinyaller.append(f'TTL={ttl} -> Linux / macOS (varsayilan: 64)')
            elif 100 <= ttl <= 128:
                skorlar['Windows'] += 25
                sinyaller.append(f'TTL={ttl} -> Windows (varsayilan: 128)')
            elif 240 <= ttl <= 255:
                skorlar['Cisco/Network'] += 25
                sinyaller.append(f'TTL={ttl} -> Cisco/Network (varsayilan: 255)')
            elif ttl <= 50:
                skorlar['Embedded/IoT'] += 18
                sinyaller.append(f'TTL={ttl} -> Muhtemelen gomulu sistem')
        else:
            print(_c('Alinamadi (ICMP engellenmis olabilir)', _F.YELLOW))

        tum_banner = {**self.banners, **self.udp_banners}
        if tum_banner:
            print(f'  {_c("->", _F.CYAN)} {len(tum_banner)} banner analiz ediliyor...')
            for port, banner in tum_banner.items():
                if banner:
                    self._banner_os_analiz(port, banner, skorlar, sinyaller)

        if self.open_ports:
            self._servis_kombo(skorlar, sinyaller)

        best = max(skorlar, key=skorlar.get)
        guven = min(int(skorlar[best]), 97)
        return {
            'os': best,
            'versiyon': self._os_versiyon(best, sinyaller),
            'guven': guven,
            'sinyaller': sinyaller,
            'skorlar': skorlar,
        }

    def os_sonuc_yazdir(self, r: Dict):
        print(f'\n{_c("=" * 60, _F.MAGENTA, True)}')
        print(f'{_c("  ISLETIM SISTEMI TESPITI", _F.MAGENTA, True)}')
        print(_c('=' * 60, _F.MAGENTA, True))
        g = r['guven']
        rk = _F.GREEN if g >= 70 else (_F.YELLOW if g >= 40 else _F.RED)
        print(f'  Tahmin : {_c(r["versiyon"], _F.WHITE, True)}')
        print(f'  Guven  : {_c(f"%{g}", rk, True)}')
        if r['sinyaller']:
            print(f'\n  {_c("Sinyaller:", _F.CYAN)}')
            for s in r['sinyaller']:
                print(f'    {_c("*", _F.CYAN)} {s}')
        print(f'\n  {_c("Puan Dagilimi:", _F.WHITE)}')
        for os_n, sc in sorted(r['skorlar'].items(), key=lambda x:-x[1]):
            if sc > 0:
                bar = _c('|' * min(int(sc/2),30), _F.MAGENTA)
                print(f'    {os_n:18s} {bar} {sc:.0f}')
        print(_c('=' * 60, _F.MAGENTA, True))

    # ── Zafiyet Kontrolu ──────────────────────────────────────────────────────
    def zafiyet_kontrol(self, port: int, banner: Optional[str] = None) -> List[Dict]:
        vulns = list(_vuln_db_al().get(port, []))
        if banner:
            b = banner.lower()
            for bc in _BANNER_CHECKS:
                bc_ports = bc['port'] if isinstance(bc['port'], list) else [bc['port']]
                if port not in bc_ports:
                    continue
                m = re.search(bc['pattern'], b, re.IGNORECASE)
                if not m:
                    continue
                groups = [int(g) for g in m.groups()]
                if bc['condition'] == 'version_lt':
                    min_ver = bc['version']
                    i = 0
                    while i < len(groups) and i < len(min_ver):
                        if groups[i] < min_ver[i]:
                            v = m.group(0).split('/')[-1] if '/' in m.group(0) else m.group(0)[:20]
                            vn = bc['vuln'].copy()
                            vn['ad'] = vn['ad'].replace('{version}', v)
                            vn['cve'] = vn.get('cve', '')
                            vulns.insert(0, vn)
                            break
                        elif groups[i] > min_ver[i]:
                            break
                        i += 1
        return vulns

    def zafiyet_raporu_yazdir(self):
        tum = sorted(set(self.open_ports + self.udp_open_ports))
        if not tum: return
        has = any(self.zafiyet_kontrol(p, self.banners.get(p)) for p in tum)
        if not has: return
        print(f'\n{_c("=" * 60, _F.RED, True)}')
        print(f'{_c("  ZAFIYET RAPORU", _F.RED, True)}')
        print(_c('=' * 60, _F.RED, True))
        for port in tum:
            banner = self.banners.get(port) or self.udp_banners.get(port)
            vulns = self.zafiyet_kontrol(port, banner)
            if not vulns: continue
            svc = SERVISLER.get(port, 'bilinmeyen')
            print(f'\n  {_c(f"Port {port}", _F.WHITE, True)} - {_c(svc, _F.CYAN)}')
            for v in vulns:
                rk, bold = SEV_RENK.get(v['sev'], (_F.WHITE, False))
                sev = _c(f'[{v["sev"]}]', rk, bold)
                cve = f' {_c(v.get("cve",""), _F.WHITE, True)}' if v.get('cve') else ''
                print(f'    {sev} {v["ad"]}{cve}')
                print(f'         {_c("Sorun:", _F.WHITE)} {v["acik"]}')
                print(f'         {_c("Cozum:", _F.GREEN)} {v["coz"]}')
        print(_c('=' * 60, _F.RED, True))

    # ── Host Discovery ────────────────────────────────────────────────────────
    def _tcp_ping(self, target: str, port: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            r = s.connect_ex((target, port))
            s.close()
            return r == 0
        except Exception:
            return False

    def _icmp_ping(self, target: str) -> Tuple[bool, Optional[int]]:
        try:
            cmd = (['ping','-n','1','-w','1500',target] if sys.platform=='win32'
                   else ['ping','-c','1','-W','2',target])
            r = subprocess.run(cmd, capture_output=True, timeout=4,
                               encoding='utf-8', errors='ignore')
            if r.returncode == 0:
                m = re.search(r'ttl=(\d+)', r.stdout, re.IGNORECASE)
                return True, (int(m.group(1)) if m else None)
            return False, None
        except Exception:
            return False, None

    def _host_kontrol(self, target: str) -> Tuple[str, bool, Optional[int]]:
        up, ttl = self._icmp_ping(target)
        if up: return target, True, ttl
        for p in (80,443,22,21,25,8080):
            if self._tcp_ping(target, p):
                return target, True, None
        return target, False, None

    async def host_discovery_calistir(self, hedefler: List[str]) -> List[Tuple[str,Optional[int]]]:
        print(f'\n{_c("Host Discovery baslatiliyor...", _F.CYAN, True)}')
        print(f'  Hedef sayi: {len(hedefler)}\n')
        canli: List[Tuple[str,Optional[int]]] = []
        sem = asyncio.Semaphore(50)
        tamamlanan: List[str] = []

        async def kontrol(t):
            async with sem:
                loop = asyncio.get_event_loop()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    r = await loop.run_in_executor(ex, self._host_kontrol, t)
                tamamlanan.append(t)
                return r

        prog = asyncio.create_task(self.progress_reporter(len(hedefler), tamamlanan))
        gorevler = [asyncio.create_task(kontrol(t)) for t in hedefler]
        for coro in asyncio.as_completed(gorevler):
            try:
                target, up, ttl = await coro
            except Exception:
                continue
            if up:
                canli.append((target, ttl))
                ttl_str = f' TTL={ttl}' if ttl else ''
                self._sonuc_yazdir(
                    f'{_c("[ACIK]", _F.GREEN, True)} '
                    f'{_c(target, _F.WHITE, True)}{_c(ttl_str, _F.CYAN)}')
        prog.cancel()
        try: await prog
        except asyncio.CancelledError: pass
        return canli

    # ── CIDR / Ag Hedef Cozumu ────────────────────────────────────────────────
    def hedefleri_coz(self, raw: str) -> List[str]:
        raw = raw.strip()
        if '/' in raw:
            try:
                net = ipaddress.ip_network(raw, strict=False)
                t = [str(ip) for ip in net.hosts()]
                print(_c(f'[OK] CIDR: {raw} -> {len(t)} host', _F.GREEN))
                return t
            except ValueError:
                print(_c(f'[HATA] Gecersiz CIDR: {raw}', _F.RED)); return []
        elif '-' in raw:
            parts = raw.split('-')
            try:
                start = ipaddress.ip_address(parts[0])
                try:
                    end = ipaddress.ip_address(parts[1])
                except ValueError:
                    base = '.'.join(parts[0].split('.')[:3])
                    end = ipaddress.ip_address(f'{base}.{parts[1]}')
                if int(start) <= int(end):
                    t = [str(ipaddress.ip_address(i)) for i in range(int(start),int(end)+1)]
                    print(_c(f'[OK] Aralik: {start}-{end} -> {len(t)} host', _F.GREEN))
                    return t
            except Exception as e:
                print(_c(f'[HATA] Aralik ayristirilamadi: {e}', _F.RED)); return []
        elif ',' in raw:
            t = [x.strip() for x in raw.split(',') if x.strip()]
            print(_c(f'[OK] Liste: {len(t)} hedef', _F.GREEN))
            return t
        return [raw]

    # ── Sonuc Ekrani ──────────────────────────────────────────────────────────
    def sonuclari_goster(self, target: str, n_port: int):
        sure = time.time() - self.scan_start_time
        print('\n' + _c('=' * 70, _F.BLUE, True))
        print(_c('                   TARAMA SONUCLARI', _F.BLUE, True))
        print(_c('=' * 70, _F.BLUE, True))
        print(f'  Hedef        : {_c(target, _F.WHITE, True)}')
        try: print(f'  IP           : {socket.gethostbyname(target)}')
        except Exception: pass
        print(f'  Taranan port : {n_port}')
        print(f'  Sure         : {sure:.2f}s')
        if sure > 0:
            print(f'  Hiz          : {_c(f"{n_port/sure:.0f} port/sn", _F.GREEN)}')
        acik = sorted(self.open_ports)
        print(f'\n  {_c(f"[+] Acik TCP portlar ({len(acik)}):", _F.GREEN, True)}')
        print('  ' + '-' * 65)
        if acik:
            for p in acik:
                svc = SERVISLER.get(p,'bilinmeyen')
                print(f'    {_c("OK", _F.GREEN)} Port {_c(str(p).rjust(5),_F.WHITE,True)}'
                      f' - {_c(svc,_F.CYAN):20s}', end='')
                if p in self.banners:
                    print(f' {_c("->",_F.WHITE)} {_c(self.banners[p][:60],_F.LIGHTCYAN_EX)}')
                else: print()
        else:
            print(f'    {_c("Acik TCP port bulunamadi.", _F.YELLOW)}')
        if self.udp_open_ports:
            print(f'\n  {_c(f"[+] Acik UDP portlar ({len(self.udp_open_ports)}):", _F.CYAN, True)}')
            for p in sorted(self.udp_open_ports):
                print(f'    {_c("OK",_F.CYAN)} Port {_c(str(p).rjust(5),_F.WHITE,True)}'
                      f' - {_c(SERVISLER.get(p,"?"),_F.CYAN)}')
        if self.filtered_ports:
            ornek = sorted(self.filtered_ports)[:10]
            print(f'\n  {_c(f"[!] Filtrelenmis ({len(self.filtered_ports)}):", _F.YELLOW)}'
                  f' {ornek}...')
        print(_c('=' * 70, _F.BLUE, True))

    # ── Sonuc Kaydetme ────────────────────────────────────────────────────────
    def _coz(self, t: str) -> str:
        try: return socket.gethostbyname(t)
        except: return t

    def _veri_olustur(self, target: str, n_port: int) -> Dict:
        sure = time.time() - (self.scan_start_time or time.time())
        portlar = []
        for p in sorted(self.open_ports):
            v = self.zafiyet_kontrol(p, self.banners.get(p))
            portlar.append({'port':p,'proto':'TCP','servis':SERVISLER.get(p,''),
                            'banner':self.banners.get(p,''),
                            'zafiyetler':[{'ad':z['ad'],'seviye':z['sev'],
                                           'cve':z.get('cve',''),'cozum':z['coz']} for z in v]})
        for p in sorted(self.udp_open_ports):
            portlar.append({'port':p,'proto':'UDP','servis':SERVISLER.get(p,''),
                            'banner':self.udp_banners.get(p,''),'zafiyetler':[]})
        return {
            'tarama':{'hedef':target,'ip':self._coz(target),'port_sayisi':n_port,
                      'sure_sn':round(sure,2),'hiz_pps':round(n_port/sure,1) if sure>0 else 0,
                      'tarih':datetime.now().isoformat()},
            'acik_portlar':portlar,
            'os_tespiti':self.os_result,
            'script_sonuclari': {str(k): v for k, v in self.script_results.items()},
            'filtrelenmis':sorted(self.filtered_ports)[:50],
        }

    def kaydetme_sor(self, target: str, n_port: int):
        if input(_c('\nSonuclari kaydet? (e/h): ', _F.CYAN)).strip().lower() != 'e':
            return
        print(_c('\nFormat: 1)JSON  2)CSV  3)TXT  4)HTML  5)NmapXML  6)Tumu', _F.CYAN))
        fmt = input(_c('Seciminiz: ', _F.CYAN)).strip()
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        base = f'scan_{target.replace(".","_").replace("/","_")}_{ts}'
        if fmt in ('1','6'): self._json_kaydet(base, target, n_port)
        if fmt in ('2','6'): self._csv_kaydet(base)
        if fmt in ('3','6'): self._txt_kaydet(base, target, n_port)
        if fmt in ('4','6'): self._html_kaydet(base, target, n_port)
        if fmt in ('5','6'): self._nmap_xml_yaz(target, f'{base}.xml', n_port)

    def _json_kaydet(self, base, target, n_port):
        path = f'{base}.json'
        with open(path,'w',encoding='utf-8') as f:
            json.dump(self._veri_olustur(target,n_port), f, ensure_ascii=False, indent=2)
        print(_c(f'[OK] JSON: {path}', _F.GREEN))

    def _csv_kaydet(self, base):
        path = f'{base}.csv'
        with open(path,'w',newline='',encoding='utf-8-sig') as f:
            w = csv.writer(f)
            w.writerow(['Port','Protokol','Servis','Zafiyet Sayisi','Max Seviye','Banner'])
            for p in sorted(self.open_ports):
                vs = self.zafiyet_kontrol(p, self.banners.get(p))
                sirali = ['KRITIK','YUKSEK','ORTA','DUSUK']
                seviyeler = [v['sev'] for v in vs]
                max_sev = next((s for s in sirali if s in seviyeler),'')
                w.writerow([p,'TCP',SERVISLER.get(p,''),len(vs),max_sev,
                             self.banners.get(p,'')[:200]])
        print(_c(f'[OK] CSV: {path}', _F.GREEN))

    def _txt_kaydet(self, base, target, n_port):
        path = f'{base}.txt'
        sure = time.time() - (self.scan_start_time or time.time())
        with open(path,'w',encoding='utf-8') as f:
            f.write('='*70+'\n  GELISMIS PORT TARAYICI v4.0 - RAPOR\n'+'='*70+'\n')
            f.write(f'  Hedef : {target}\n  IP    : {self._coz(target)}\n')
            f.write(f'  Port  : {n_port}\n  Sure  : {sure:.2f}s\n')
            f.write(f'  Tarih : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n')
            f.write(f'ACIK PORTLAR:\n'+'-'*50+'\n')
            for p in sorted(self.open_ports):
                svc = SERVISLER.get(p,'?')
                banner = self.banners.get(p,'')
                f.write(f'  [TCP] {p:5d} - {svc:15s}')
                if banner: f.write(f' | {banner[:80]}')
                f.write('\n')
                for v in self.zafiyet_kontrol(p, banner):
                    cve = f' ({v.get("cve","")})' if v.get('cve') else ''
                    f.write(f'    [{v["sev"]}] {v["ad"]}{cve}\n')
                    f.write(f'      Cozum: {v["coz"]}\n')
            if self.os_result:
                f.write(f'\nOS TESPITI:\n  {self.os_result["versiyon"]} (%{self.os_result["guven"]} guven)\n')
            if self.script_results:
                f.write(f'\nSCRIPT SONUCLARI:\n'+'-'*50+'\n')
                for port, bulgular in self.script_results.items():
                    svc = SERVISLER.get(port, '?')
                    f.write(f'  Port {port} ({svc}):\n')
                    for b in bulgular:
                        cve = f' ({b.get("cve","")})' if b.get('cve') else ''
                        f.write(f'    [{b["sev"]}] {b["ad"]}{cve}\n')
                        f.write(f'      Cozum: {b.get("coz","")}\n')
        print(_c(f'[OK] TXT: {path}', _F.GREEN))

    def _html_kaydet(self, base, target, n_port):
        path = f'{base}.html'
        sure = time.time() - (self.scan_start_time or time.time())
        SEV_COL = {'KRITIK':'#ff4444','YUKSEK':'#ff8800','ORTA':'#ffcc00','DUSUK':'#44aaff'}
        satirlar = ''
        for p in sorted(self.open_ports):
            svc = SERVISLER.get(p,'-')
            banner = self.banners.get(p,'')
            vs = self.zafiyet_kontrol(p, banner)
            v_html = ''.join(
                f'<span class="badge" style="background:{SEV_COL.get(v["sev"],"#888")}">'
                f'{v["sev"]}</span> {v["ad"]}'
                f'{(" <code>"+v.get("cve","")+"</code>") if v.get("cve") else ""}<br>'
                for v in vs) or '-'
            satirlar += (f'<tr><td>{p}</td><td>TCP</td><td>{svc}</td>'
                         f'<td class="bn">{banner[:100]}</td>'
                         f'<td>{v_html}</td></tr>\n')
        for p in sorted(self.udp_open_ports):
            satirlar += (f'<tr><td>{p}</td><td>UDP</td>'
                         f'<td>{SERVISLER.get(p,"-")}</td><td>-</td><td>-</td></tr>\n')
        script_blok = ''
        if self.script_results:
            scr_html = ''
            for port, bulgular in self.script_results.items():
                svc = SERVISLER.get(port, '?')
                b_html = ''.join(
                    f'<div style="margin:4px 0;padding:4px 8px;background:#1c2128;'
                    f'border-left:3px solid {SEV_COL.get(b.get("sev","DUSUK"),"#888")}">'
                    f'<span class="badge" style="background:{SEV_COL.get(b.get("sev","DUSUK"),"#888")}">'
                    f'{b["sev"]}</span> <b>{b["ad"]}</b>'
                    f'{" (" + b.get("cve","") + ")" if b.get("cve") else ""}'
                    f'<br><span style="color:#8b949e;font-size:.85em">{b.get("acik","")[:150]}</span>'
                    f'</div>'
                    for b in bulgular
                )
                scr_html += f'<tr><td>{port}</td><td>{svc}</td><td>{b_html}</td></tr>\n'
            script_blok = (
                f'<h3 style="color:#bc8cff;margin-top:24px">Script Tarama Sonuclari</h3>'
                f'<table><tr><th>Port</th><th>Servis</th><th>Bulgular</th></tr>'
                f'{scr_html}</table>'
            )
        os_blok = ''
        if self.os_result:
            sigs = '<br>'.join(self.os_result.get('sinyaller',[]))
            os_blok = (f'<div class="os"><h3>OS Tespiti</h3>'
                       f'<p><b>Tahmin:</b> {self.os_result["versiyon"]}</p>'
                       f'<p><b>Guven:</b> %{self.os_result["guven"]}</p>'
                       f'<p>{sigs}</p></div>')
        html = f'''<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8">
<title>Port Tarama - {target}</title><style>
*{{box-sizing:border-box}} body{{font-family:Segoe UI,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}}
h1{{color:#58a6ff}} h3{{color:#79c0ff}}
.info{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:16px}}
.info span{{color:#58a6ff;font-weight:bold}}
table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden}}
th{{background:#21262d;color:#79c0ff;padding:10px;text-align:left}}
td{{padding:8px 10px;border-bottom:1px solid #21262d;font-size:.9em}}
tr:hover{{background:#1c2128}} .bn{{color:#8b949e;font-size:.8em;max-width:250px}}
.badge{{color:#fff;padding:2px 6px;border-radius:4px;font-size:.75em;font-weight:bold;margin-right:4px}}
.os{{background:#161b22;border:1px solid #8957e5;border-radius:8px;padding:16px;margin:16px 0}}
code{{background:#21262d;padding:2px 5px;border-radius:3px;font-size:.85em}}
</style></head><body>
<h1>Port Tarama Raporu</h1>
<div class="info">
<p>Hedef: <span>{target}</span> | IP: <span>{self._coz(target)}</span></p>
<p>Port: <span>{n_port}</span> | Sure: <span>{sure:.2f}s</span>
   | Acik: <span>{len(self.open_ports)+len(self.udp_open_ports)}</span>
   | Tarih: <span>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span></p>
</div>
{os_blok}
{script_blok}
<h3>Acik Portlar</h3>
<table><tr><th>Port</th><th>Proto</th><th>Servis</th><th>Banner</th><th>Zafiyet</th></tr>
{satirlar or "<tr><td colspan='5'>Acik port bulunamadi.</td></tr>"}
</table>
<p style="margin-top:16px;color:#484f58;font-size:.8em">Gelismis Port Tarayici v4.0</p>
</body></html>'''
        with open(path,'w',encoding='utf-8') as f:
            f.write(html)
        print(_c(f'[OK] HTML: {path}', _F.GREEN))

    # ── Tarama Modlari ────────────────────────────────────────────────────────
    def _sifirla(self):
        self.open_ports=[];self.filtered_ports=[]
        self.udp_open_ports=[];self.banners={}
        self.udp_banners={};self.os_result=None
        self.script_results={};self.syn_scan=False

    def _script_modullerini_yukle(self):
        scripts_dir = pathlib.Path(__file__).parent / 'scripts'
        if not scripts_dir.is_dir():
            return
        self._scripts = []
        for py_file in sorted(scripts_dir.glob('*.py')):
            if py_file.name.startswith('_'):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    py_file.stem, str(py_file))
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if not hasattr(mod, 'check') or not hasattr(mod, 'PORTS'):
                    continue
                self._scripts.append({
                    'name': getattr(mod, 'NAME', py_file.stem),
                    'desc': getattr(mod, 'DESCRIPTION', ''),
                    'ports': mod.PORTS,
                    'risk': getattr(mod, 'RISK', 'BILINMIYOR'),
                    'author': getattr(mod, 'AUTHOR', ''),
                    'check': mod.check,
                    'file': py_file.name,
                })
            except Exception:
                pass

    def _scriptleri_calistir(self, target: str):
        if not self._scripts:
            return
        print(f'\n{_c("Script motoru calistiriliyor...", _F.MAGENTA, True)}')
        print(f'  {_c(f"Yuklu: {len(self._scripts)} script", _F.CYAN)}')
        self.script_results = {}
        for script in self._scripts:
            script_name = script['name']
            for port in self.open_ports + self.udp_open_ports:
                if port not in script['ports']:
                    continue
                use_ssl_flag = port in (443, 8443, 636, 993, 995, 465)
                try:
                    res = script['check'](target, port, use_ssl_flag)
                except Exception:
                    continue
                if res:
                    if port not in self.script_results:
                        self.script_results[port] = []
                    self.script_results[port].extend(res)
                    svc = SERVISLER.get(port, '?')
                    rk = SEV_RENK.get(script['risk'], (_F.WHITE, False))[0]
                    print(f'  {_c("[SCRIPT]", _F.MAGENTA)}'
                          f' {_c(script_name, _F.WHITE, True)}'
                          f' -> Port {_c(str(port), _F.CYAN)}'
                          f' ({svc}): {_c(f"{len(res)} bulgu", rk)})')
                    for r in res[:2]:
                        rk2, _ = SEV_RENK.get(r.get('sev', 'DUSUK'), (_F.WHITE, False))
                        print(f'    {_c("-> " + r["ad"], rk2)}')
        self._script_sonuc_yazdir()
        print()

    def _script_sonuc_yazdir(self):
        if not self.script_results:
            return
        print(f'\n{_c("=" * 60, _F.MAGENTA, True)}')
        print(f'{_c("  SCRIPT TARAMA SONUCLARI", _F.MAGENTA, True)}')
        print(_c('=' * 60, _F.MAGENTA, True))
        for port, bulgular in self.script_results.items():
            svc = SERVISLER.get(port, '?')
            print(f'\n  {_c(f"Port {port} ({svc})", _F.WHITE, True)}')
            for b in bulgular:
                rk, bold = SEV_RENK.get(b.get('sev', 'DUSUK'), (_F.WHITE, False))
                sev = _c(f'[{b["sev"]}]', rk, bold)
                print(f'    {sev} {b["ad"]}')
                if b.get('acik'):
                    print(f'         {_c("Sorun:", _F.WHITE)} {b["acik"][:100]}')
                if b.get('coz'):
                    print(f'         {_c("Cozum:", _F.GREEN)} {b["coz"][:100]}')
        print(_c('=' * 60, _F.MAGENTA, True))

    def _hata_isle(self, e: Exception):
        print(_c(f'\n[HATA] {e}', _F.RED))
        print('  Cozum: es-zamanli sayiyi dusurun veya timeout artirin')

    # ── SYN Scan (Half-Open) ───────────────────────────────────────────────────
    _SCAPY_VAR: bool = False

    def _scapy_kontrol(self) -> bool:
        try:
            import scapy.all as _sa
            self.__class__._SCAPY_VAR = True
            return True
        except ImportError:
            return False

    def _syn_port_test(self, target: str, port: int) -> Tuple[int, bool]:
        try:
            from scapy.all import IP, TCP, sr1
            pkt = IP(dst=target) / TCP(dport=port, flags='S')
            ans = sr1(pkt, timeout=self.timeout, verbose=0)
            if ans is None:
                return port, False
            if ans.haslayer(TCP):
                flags = ans[TCP].flags
                if flags & 0x12 == 0x12:  # SYN-ACK
                    rst = IP(dst=target) / TCP(dport=port, flags='R')
                    sr1(rst, timeout=0.5, verbose=0)
                    return port, True
                elif flags & 0x14 == 0x14:  # RST-ACK -> closed
                    return port, False
            return port, False
        except Exception:
            return port, False

    async def _syn_port_tara(self, target: str, port: int) -> Tuple[int, str, Optional[str]]:
        async with self.semaphore:
            try:
                loop = asyncio.get_event_loop()
                port, acik = await loop.run_in_executor(
                    self.executor, self._syn_port_test, target, port)
                return port, ('open' if acik else 'closed'), None
            except Exception as e:
                return port, 'error', str(e)

    async def syn_tarama_calistir(self, target: str, portlar: List[int]):
        if not self._scapy_kontrol():
            print(_c('\n[HATA] Scapy kurulu degil! pip install scapy', _F.RED))
            return
        self.syn_scan = True
        print(f'\n{_c("SYN (Half-Open) Tarama baslatiliyor...", _F.CYAN, True)}')
        print(f'  {_c("NOT: Yonetici yetkisi gerektirir!", _F.YELLOW)}')
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        tamamlanan: List[int] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent) as ex:
            self.executor = ex
            prog = asyncio.create_task(self.progress_reporter(len(portlar), tamamlanan))
            gorevler = [asyncio.create_task(self._syn_port_tara(target, p)) for p in portlar]
            for coro in asyncio.as_completed(gorevler):
                try:
                    r = await coro
                except Exception:
                    continue
                if isinstance(r, Exception):
                    continue
                port, durum, _ = r
                tamamlanan.append(port)
                if durum == 'open':
                    self.open_ports.append(port)
                    self._acik_port_yazdir(port, None)
            prog.cancel()
            try:
                await prog
            except asyncio.CancelledError:
                pass
            self.executor = None

    # ── Nmap XML Cikti ─────────────────────────────────────────────────────────
    def _nmap_xml_yaz(self, target: str, path: str, n_port: int):
        root = ET.Element('nmaprun')
        root.set('scanner', 'AHUScanner')
        root.set('args', f'ahu-scan {target}')
        root.set('start', str(int((self.scan_start_time or time.time()))))
        root.set('version', '4.0')
        root.set('xmloutputversion', '1.05')

        scaninfo = ET.SubElement(root, 'scaninfo')
        scaninfo.set('type', 'connect')
        scaninfo.set('protocol', 'tcp')
        scaninfo.set('numservices', str(n_port))

        host_elem = ET.SubElement(root, 'host')
        ET.SubElement(host_elem, 'status', state='up')
        addr = ET.SubElement(host_elem, 'address')
        addr.set('addr', self._coz(target))
        addr.set('addrtype', 'ipv4')
        hostnames = ET.SubElement(host_elem, 'hostnames')
        ET.SubElement(hostnames, 'hostname', name=target, type='user')

        ports_elem = ET.SubElement(host_elem, 'ports')
        for p in sorted(self.open_ports):
            port_e = ET.SubElement(ports_elem, 'port')
            port_e.set('protocol', 'tcp')
            port_e.set('portid', str(p))
            state = ET.SubElement(port_e, 'state')
            state.set('state', 'open')
            svc = ET.SubElement(port_e, 'service')
            svc.set('name', SERVISLER.get(p, 'unknown'))
            if p in self.banners and self.banners[p]:
                svc.set('product', self.banners[p][:80])
                banners_extracted = re.findall(r'([\w-]+)/(\d+\.\d+)', self.banners[p])
                if banners_extracted:
                    svc.set('product', banners_extracted[0][0])
                    svc.set('version', banners_extracted[0][1])
            for v in self.zafiyet_kontrol(p, self.banners.get(p)):
                scr = ET.SubElement(port_e, 'script')
                scr.set('id', v.get('cve', v['ad']))
                scr.set('output', f"[{v['sev']}] {v['ad']}: {v['acik']} | Cozum: {v['coz']}")
        for p in sorted(self.udp_open_ports):
            port_e = ET.SubElement(ports_elem, 'port')
            port_e.set('protocol', 'udp')
            port_e.set('portid', str(p))
            state = ET.SubElement(port_e, 'state')
            state.set('state', 'open')
            svc = ET.SubElement(port_e, 'service')
            svc.set('name', SERVISLER.get(p, 'unknown'))

        if self.os_result:
            os_e = ET.SubElement(host_elem, 'os')
            osm = ET.SubElement(os_e, 'osmatch')
            osm.set('name', self.os_result['versiyon'])
            osm.set('accuracy', str(self.os_result['guven']))
            for signal in self.os_result.get('sinyaller', []):
                oscl = ET.SubElement(osm, 'osclass')
                oscl.set('type', signal[:60])

        runstats = ET.SubElement(root, 'runstats')
        finished = ET.SubElement(runstats, 'finished')
        finished.set('time', str(int(time.time())))
        finished.set('summary', f'{len(self.open_ports)+len(self.udp_open_ports)} open ports')

        tree = ET.ElementTree(root)
        ET.indent(tree, space='  ')
        tree.write(path, encoding='utf-8', xml_declaration=True)
        print(_c(f'[OK] Nmap XML: {path}', _F.GREEN))

    def tarama_baslat(self, target: str, portlar: List[int], tip: str = 'TCP'):
        self._sifirla()
        self.scan_start_time = time.time()
        try:
            asyncio.run(self.tarama_calistir(target, portlar))
            self.sonuclari_goster(target, len(portlar))
            if self.os_sor():
                print(f'\n{_c("OS tespiti yapiliyor...", _F.CYAN)}')
                self.os_result = self.os_tespit(target)
                self.os_sonuc_yazdir(self.os_result)
            self.zafiyet_raporu_yazdir()
            self._scriptleri_calistir(target)
            self.kaydetme_sor(target, len(portlar))
        except KeyboardInterrupt:
            print(_c('\n[!] Tarama durduruldu.', _F.YELLOW))
        except Exception as e:
            self._hata_isle(e)
        input(_c('\nDevam icin Enter a basin...', _F.WHITE))

    HIZLI_PORTLAR = [
        21,22,23,25,53,67,80,110,111,123,135,137,139,143,161,
        389,443,445,465,587,636,993,995,1433,1521,2049,2375,
        3000,3306,3389,5000,5432,5601,5900,6379,8000,8080,
        8443,8888,9000,9090,9200,11211,27017,
    ]

    def hizli_tarama(self):
        t = self.hedef_al(); self.profil_sec()
        self.grab_banner = self.banner_sor()
        self.tarama_baslat(t, self.HIZLI_PORTLAR)

    def ozel_aralik(self):
        t = self.hedef_al()
        print(_c('\nPort araligi:', _F.CYAN))
        s, e = self.port_araligi_al()
        portlar = list(range(s, e+1))
        if len(portlar) > 10000:
            est = len(portlar)/(self.max_concurrent/self.timeout)/60
            print(_c(f'\n[UYARI] {len(portlar)} port -> tahmini {est:.1f} dk', _F.YELLOW))
            if input('Devam? (e/h): ').lower() != 'e': return
        self.profil_sec()
        self.grab_banner = self.banner_sor()
        self.tarama_baslat(t, portlar)

    def tam_tarama(self):
        t = self.hedef_al()
        est = 65535/(self.max_concurrent/self.timeout)/60
        print(_c(f'\n[UYARI] 65535 port -> tahmini ~{est:.1f} dk', _F.YELLOW))
        if input('Devam? (e/h): ').lower() != 'e': return
        self.profil_sec()
        self.grab_banner = False
        print(_c('[NOT] Banner grabbing performans icin devre disi.', _F.YELLOW))
        self.tarama_baslat(t, list(range(1, 65536)))

    def banner_tarama(self):
        t = self.hedef_al(); self.profil_sec()
        self.grab_banner = True
        self.tarama_baslat(t, self.HIZLI_PORTLAR, 'TCP-Banner')

    def udp_tarama_menu(self):
        UDP_PORTLAR = [53,67,69,111,123,137,138,161,162,389,
                       514,520,1194,1434,1900,4500,5353,5060,5353,49152]
        print(_c('\nUDP Tarama Modu', _F.CYAN, True))
        print('  1. Yaygin UDP portlari\n  2. Ozel UDP aralik')
        sec = input(_c('Seciminiz: ', _F.CYAN)).strip()
        t = self.hedef_al(); self.profil_sec()
        portlar = UDP_PORTLAR
        if sec == '2':
            print(_c('\nPort araligi:', _F.CYAN))
            s, e = self.port_araligi_al()
            portlar = list(range(s, e+1))
        self._sifirla()
        self.scan_start_time = time.time()
        try:
            asyncio.run(self.udp_tarama_calistir(t, portlar))
        except KeyboardInterrupt:
            print(_c('\n[!] Durduruldu.', _F.YELLOW))
        except Exception as e:
            self._hata_isle(e)
        sure = time.time() - self.scan_start_time
        print(f'\n{_c("UDP Sonuclari:", _F.CYAN, True)}')
        print(f'  Taranan: {len(portlar)} port | Sure: {sure:.2f}s')
        print(f'  Acik UDP: {_c(str(len(self.udp_open_ports)), _F.GREEN, True)}')
        for p in sorted(self.udp_open_ports):
            print(f'    {_c("OK", _F.CYAN)} Port {p} - {SERVISLER.get(p,"?")}')
        self.zafiyet_raporu_yazdir()
        self.kaydetme_sor(t, len(portlar))
        input(_c('\nDevam icin Enter a basin...', _F.WHITE))

    def syn_tarama_menu(self):
        print(_c('\nSYN Half-Open Tarama Modu', _F.CYAN, True))
        print(_c('  NOT: Yonetici/root yetkisi GEREKTIRIR!', _F.YELLOW, True))
        print(_c('  Bu yontem TCP 3-way handshake tamamlamaz - gizlidir.', _F.WHITE))
        print('  1. Hizli portlar\n  2. Ozel aralik\n  3. Tum portlar')
        sec = input(_c('\nSeciminiz: ', _F.CYAN)).strip()
        if sec == '1': portlar = self.HIZLI_PORTLAR
        elif sec == '2':
            t = self.hedef_al()
            print(_c('\nPort araligi:', _F.CYAN))
            s, e = self.port_araligi_al()
            portlar = list(range(s, e+1))
            self._sifirla()
            self.scan_start_time = time.time()
            try:
                asyncio.run(self.syn_tarama_calistir(t, portlar))
                self.sonuclari_goster(t, len(portlar))
                self.zafiyet_raporu_yazdir()
                self.kaydetme_sor(t, len(portlar))
            except KeyboardInterrupt:
                print(_c('\n[!] Durduruldu.', _F.YELLOW))
            except Exception as e:
                self._hata_isle(e)
            input(_c('\nDevam icin Enter a basin...', _F.WHITE))
            return
        elif sec == '3':
            est = 65535/(self.max_concurrent/self.timeout)/60
            print(_c(f'\n[UYARI] 65535 port SYN tarama -> tahmini ~{est:.1f} dk', _F.YELLOW))
            if input('Devam? (e/h): ').lower() != 'e': return
            portlar = list(range(1, 65536))
        else: return
        t = self.hedef_al(); self.profil_sec()
        self._sifirla(); self.scan_start_time = time.time()
        try:
            asyncio.run(self.syn_tarama_calistir(t, portlar))
            self.sonuclari_goster(t, len(portlar))
            self.zafiyet_raporu_yazdir()
            self.kaydetme_sor(t, len(portlar))
        except KeyboardInterrupt:
            print(_c('\n[!] Durduruldu.', _F.YELLOW))
        except Exception as e:
            self._hata_isle(e)
        input(_c('\nDevam icin Enter a basin...', _F.WHITE))

    def ag_cidr_tarama(self):
        print(_c('\nAg/CIDR Tarama Modu', _F.CYAN, True))
        print('  Ornek: 192.168.1.0/24  |  10.0.0.1-10.0.0.50  |  10.0.0.1,10.0.0.2')
        raw = input(_c('Hedef(ler): ', _F.CYAN)).strip()
        hedefler = self.hedefleri_coz(raw)
        if not hedefler:
            input(_c('Enter a basin...', _F.WHITE)); return
        if len(hedefler) > 1000:
            print(_c(f'[UYARI] {len(hedefler)} hedef cok fazla!', _F.YELLOW))
            if input('Devam? (e/h): ').lower() != 'e': return

        tarama_hedefleri = hedefler
        if input(_c('\nOnce host discovery? (e/h): ', _F.CYAN)).lower() == 'e':
            canli = asyncio.run(self.host_discovery_calistir(hedefler))
            print(f'\n{_c(f"Aktif: {len(canli)}/{len(hedefler)}", _F.GREEN, True)}')
            if not canli:
                input(_c('Enter a basin...', _F.WHITE)); return
            tarama_hedefleri = [h for h,_ in canli]

        print(_c('\nPortlar: 1)Hizli  2)Ozel aralik', _F.CYAN))
        pc = input(_c('Seciminiz: ', _F.CYAN)).strip()
        portlar = self.HIZLI_PORTLAR
        if pc == '2':
            print(_c('\nPort araligi:', _F.CYAN))
            s, e = self.port_araligi_al()
            portlar = list(range(s, e+1))

        self.profil_sec()
        self.grab_banner = self.banner_sor()

        tum_sonuclar: Dict[str,List[int]] = {}
        for i, t in enumerate(tarama_hedefleri, 1):
            print(f'\n{_c(f"[{i}/{len(tarama_hedefleri)}]", _F.YELLOW)} -> {_c(t, _F.WHITE, True)}')
            self._sifirla()
            self.scan_start_time = time.time()
            try:
                asyncio.run(self.tarama_calistir(t, portlar))
                if self.open_ports:
                    tum_sonuclar[t] = list(self.open_ports)
                    self.sonuclari_goster(t, len(portlar))
            except KeyboardInterrupt:
                print(_c('\n[!] Durduruldu.', _F.YELLOW)); break
            except Exception as e:
                self._hata_isle(e)

        print(f'\n{_c("=" * 50, _F.BLUE, True)}')
        print(_c('  AG TARAMA OZETI', _F.BLUE, True))
        print(_c('=' * 50, _F.BLUE, True))
        for host, op in tum_sonuclar.items():
            print(f'  {_c(host, _F.WHITE, True):20s} -> {_c(str(len(op)), _F.GREEN)} acik port')
            for p in op[:5]:
                print(f'    {_c("*", _F.CYAN)} {p} ({SERVISLER.get(p,"?")})')
        print(_c('=' * 50, _F.BLUE, True))
        input(_c('\nDevam icin Enter a basin...', _F.WHITE))

    def host_discovery_menu(self):
        print(_c('\nHost Discovery (Ping Sweep)', _F.CYAN, True))
        print('  CIDR, aralik veya tek IP girin.')
        raw = input(_c('Hedef(ler): ', _F.CYAN)).strip()
        hedefler = self.hedefleri_coz(raw)
        if not hedefler:
            input(_c('Enter a basin...', _F.WHITE)); return

        canli = asyncio.run(self.host_discovery_calistir(hedefler))

        print(f'\n{_c("=" * 50, _F.GREEN, True)}')
        print(f'{_c("  AKTIF HOSTLAR", _F.GREEN, True)}: {len(canli)} / {len(hedefler)}')
        print(_c('=' * 50, _F.GREEN, True))
        for host, ttl in canli:
            ttl_str = f' TTL={ttl}' if ttl else ''
            hint = ''
            if ttl:
                if 50 <= ttl <= 65: hint = ' -> Linux/macOS'
                elif 100 <= ttl <= 128: hint = ' -> Windows'
                elif ttl >= 240: hint = ' -> Cisco/Network'
            print(f'  {_c("O", _F.GREEN)} {_c(host, _F.WHITE, True)}'
                  f'{_c(ttl_str, _F.CYAN)}{_c(hint, _F.YELLOW)}')
        print(_c('=' * 50, _F.GREEN, True))

        if canli and input(_c('\nAktif hostlari port tara? (e/h): ', _F.CYAN)).lower() == 'e':
            KISA = [22,80,443,3389,445,8080,3306,5432,25,21]
            for host, _ in canli:
                print(f'\n{_c("-> Taraniyor:", _F.CYAN)} {host}')
                self._sifirla(); self.scan_start_time = time.time()
                self.grab_banner = False
                try:
                    asyncio.run(self.tarama_calistir(host, KISA))
                    self.sonuclari_goster(host, len(KISA))
                except Exception as e:
                    self._hata_isle(e)

        input(_c('\nDevam icin Enter a basin...', _F.WHITE))

    # ── Gelismis Ayarlar ──────────────────────────────────────────────────────
    def gelismis_ayarlar(self):
        while True:
            self.temizle()
            print(_c('\n[ GELISMIS AYARLAR ]', _F.BLUE, True))
            print(_c('-' * 45, _F.BLUE))
            print(f'  1. Timeout  (su an: {_c(str(self.timeout)+"s", _F.YELLOW)})')
            print(f'  2. Es zamanli baglanti (su an: {_c(str(self.max_concurrent), _F.YELLOW)})')
            print(f'  3. Hazir profil sec')
            print(f'  4. Colorama kur (renk icin: pip install colorama)')
            print(f'  5. Script motoru ({len(self._scripts)} script yuklu)')
            print(f'  6. Ana menuye don')
            print(_c('-' * 45, _F.BLUE))
            sec = input(_c('\nSeciminiz (1-6): ', _F.CYAN)).strip()
            if sec == '1':
                try:
                    v = float(input('Yeni timeout (0.1-5.0s): '))
                    if 0.1 <= v <= 5.0: self.timeout = v; print(_c(f'[OK] {v}s', _F.GREEN))
                    else: print(_c('[HATA] 0.1-5.0 arasinda olmali!', _F.RED))
                except ValueError: print(_c('[HATA] Gecersiz!', _F.RED))
            elif sec == '2':
                try:
                    v = int(input('Yeni es-zamanli (50-2000): '))
                    if 50 <= v <= 2000: self.max_concurrent = v; print(_c(f'[OK] {v}', _F.GREEN))
                    else: print(_c('[HATA] 50-2000 arasinda olmali!', _F.RED))
                except ValueError: print(_c('[HATA] Gecersiz!', _F.RED))
            elif sec == '3':
                self.profil_sec()
            elif sec == '4':
                os.system(f'{sys.executable} -m pip install colorama')
                print(_c('Lutfen programi yeniden baslatin.', _F.YELLOW))
            elif sec == '5':
                self._script_listele()
            elif sec == '6':
                break
            else:
                print(_c('[HATA] Gecersiz secim!', _F.RED))
            input(_c('\nDevam icin Enter a basin...', _F.WHITE))

    def _script_listele(self):
        if not self._scripts:
            print(_c('\n[!] Yuklu script bulunamadi.', _F.YELLOW))
            print(_c('  Scriptler `scripts/` klasorune .py dosyasi olarak eklenir.', _F.WHITE))
            return
        print(_c(f'\n[ YUKLU SCRIPTLER ({len(self._scripts)}) ]', _F.MAGENTA, True))
        print(_c('-' * 60, _F.MAGENTA))
        for s in self._scripts:
            ports_str = ','.join(str(p) for p in s['ports'][:6])
            if len(s['ports']) > 6:
                ports_str += '...'
            rk = SEV_RENK.get(s['risk'], (_F.WHITE, False))[0]
            print(f'  {_c(s["name"], _F.WHITE, True)} ({_c(s["risk"], rk)})')
            print(f'    Port: {_c(ports_str, _F.CYAN)}')
            print(f'    {s["desc"]}')
        print(_c('-' * 60, _F.MAGENTA))


# ── Ana Fonksiyon ─────────────────────────────────────────────────────────────
def main():
    scanner = AdvancedPortScanner()
    def _sig(sig, frame):
        print(_c('\nProgram kapatildi.', _F.YELLOW)); sys.exit(0)
    signal.signal(signal.SIGINT, _sig)
    if not _HAS_COLOR:
        print('[BILGI] Renkli cikti icin: pip install colorama\n')
    try:
        scanner.menu_goster()
    except KeyboardInterrupt:
        print(_c('\nProgram kapatildi.', _F.YELLOW)); sys.exit(0)

if __name__ == '__main__':
    main()
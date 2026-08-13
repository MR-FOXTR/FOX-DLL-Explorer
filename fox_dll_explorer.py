#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FOX DLL Explorer
=================
Windows DLL/EXE dosyalarini analiz eden tek dosyalik Python araci.

Ozellikler:
- .NET Assembly / Native PE tespiti
- .NET dosyalar icin ilspycmd ile decompile (varsa)
- PE Info, Imports, Win API, Exports, Strings, Assembly (Capstone disassembly)
- Supheli API tespiti + risk skoru (dairesel gosterge)
- customtkinter ile karanlik temali, kart tabanli GUI

Kurulum:
    pip install customtkinter pefile capstone

.NET decompile ozelligi icin (opsiyonel, sistemde varsa otomatik kullanilir):
    dotnet tool install -g ilspycmd

Calistirma:
    python fox_dll_explorer.py
"""

import os
import re
import sys
import hashlib
import threading
import subprocess
import traceback
from datetime import datetime

# ---------------------------------------------------------------------------
# Bagimlilik kontrolleri (kullaniciya net hata mesaji vermek icin)
# ---------------------------------------------------------------------------
MISSING_DEPS = []

try:
    import customtkinter as ctk
except ImportError:
    MISSING_DEPS.append("customtkinter")

try:
    import pefile
except ImportError:
    MISSING_DEPS.append("pefile")

try:
    import capstone
except ImportError:
    MISSING_DEPS.append("capstone")

if MISSING_DEPS:
    print("Eksik kutuphaneler bulundu: " + ", ".join(MISSING_DEPS))
    print("Kurulum icin: pip install " + " ".join(MISSING_DEPS))
    sys.exit(1)

from tkinter import filedialog, messagebox
import tkinter as tk


# ===========================================================================
# SABITLER
# ===========================================================================

# Supheli API kategorileri -> fonksiyon listesi
SUSPICIOUS_APIS = {
    "Process / Injection": [
        "OpenProcess", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx", "VirtualAllocEx",
        "VirtualProtectEx", "NtUnmapViewOfSection", "SetThreadContext",
        "QueueUserAPC", "NtCreateThreadEx", "Process32First", "Process32Next",
        "Toolhelp32ReadProcessMemory",
    ],
    "Keyboard / Input (Keylogger)": [
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
        "keybd_event", "GetKeyboardState", "MapVirtualKey",
        "RegisterRawInputDevices", "GetForegroundWindow",
    ],
    "Network": [
        "socket", "connect", "send", "recv", "WSAStartup", "WSASocket",
        "InternetOpen", "InternetOpenUrl", "InternetReadFile",
        "URLDownloadToFile", "HttpSendRequest", "gethostbyname",
        "bind", "listen", "accept",
    ],
    "Screen / Capture": [
        "BitBlt", "CreateCompatibleBitmap", "CreateCompatibleDC",
        "GetDC", "GetWindowDC", "StretchBlt",
    ],
    "Registry": [
        "RegOpenKey", "RegOpenKeyEx", "RegSetValue", "RegSetValueEx",
        "RegCreateKey", "RegCreateKeyEx", "RegDeleteKey", "RegDeleteValue",
        "RegQueryValueEx",
    ],
    "Anti-Debug / Evasion": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
    ],
    "Persistence / Service": [
        "CreateService", "StartService", "OpenSCManager",
        "RegisterServiceCtrlHandler", "WinExec", "ShellExecute", "CreateProcess",
    ],
    "Crypto / Packer": [
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
        "VirtualAlloc", "VirtualProtect", "LoadLibrary", "GetProcAddress",
    ],
}

# Win API sekmesi icin: hangi sistem DLL'i hangi kategoriye ait (genel siniflandirma)
WINAPI_DLL_CATEGORIES = {
    "kernel32.dll": "Cekirdek / Sistem",
    "kernelbase.dll": "Cekirdek / Sistem",
    "ntdll.dll": "Cekirdek / Sistem (Native)",
    "advapi32.dll": "Guvenlik / Registry / Servis",
    "user32.dll": "Kullanici Arayuzu / Girdi",
    "gdi32.dll": "Grafik (GDI)",
    "gdiplus.dll": "Grafik (GDI+)",
    "shell32.dll": "Kabuk (Shell)",
    "shlwapi.dll": "Kabuk (Shell) Yardimci",
    "ole32.dll": "COM / OLE",
    "oleaut32.dll": "COM / OLE Otomasyon",
    "comctl32.dll": "Ortak Kontroller (UI)",
    "ws2_32.dll": "Ag / Soket",
    "wininet.dll": "Ag / Internet",
    "winhttp.dll": "Ag / HTTP",
    "urlmon.dll": "Ag / URL Indirme",
    "crypt32.dll": "Kriptografi",
    "bcrypt.dll": "Kriptografi (CNG)",
    "mscoree.dll": ".NET CLR",
    "psapi.dll": "Process Bilgisi",
    "iphlpapi.dll": "Ag / IP Yardimci",
    "dbghelp.dll": "Debug / Sembol",
    "version.dll": "Surum Bilgisi",
    "winmm.dll": "Multimedya",
    "setupapi.dll": "Kurulum / Surucu",
    "netapi32.dll": "Ag Yonetimi",
}

# String filtreleri icin regex kaliplari.
# NOT: Ic ice grup kullanilan desenlerde findall() tuple donduruyor (bytes degil),
# bu yuzden tum eslesmeyi almak icin non-capturing group (?:...) kullaniyoruz.
# Boylece findall() her zaman tek bir bytes nesnesi listesi dondurur ve
# ".decode()" guvenle cagrilabilir -> "'tuple' object has no attribute 'decode'" hatasi cozulur.
RE_URL = re.compile(rb"(?:https?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
RE_IP = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_REGISTRY = re.compile(rb"(?:HKEY_[A-Z_]+|SOFTWARE\\\\[A-Za-z0-9_\\\\]+)")
RE_FILEPATH = re.compile(rb"[A-Za-z]:\\\\[^\"\x00<>|\r\n]{3,}")
RE_CMDLINE = re.compile(rb"(?:cmd\.exe|powershell(?:\.exe)?|/c\s|\-EncodedCommand|rundll32)", re.IGNORECASE)

ASCII_MIN_LEN = 4
UNICODE_MIN_LEN = 4


# ===========================================================================
# ANALIZ MOTORU
# ===========================================================================

class AnalysisResult:
    """Tek bir dosya analizi sonucunu tutan konteyner sinifi."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.is_dotnet = False
        self.is_native_pe = False
        self.error = None

        # PE bilgisi
        self.info = {}
        # Imports: {dll_adi: [fonksiyonlar]}
        self.imports = {}
        # Exports: [fonksiyon isimleri]
        self.exports = []
        # Stringler
        self.ascii_strings = []
        self.unicode_strings = []
        self.filtered = {"url": [], "ip": [], "registry": [], "filepath": [], "cmdline": []}
        # Disassembly satirlari (adres, mnemonic, ops)
        self.disasm_lines = []
        # Supheli API bulgular: {kategori: [(dll, api), ...]}
        self.suspicious_hits = {}
        # .NET decompile ciktisi
        self.decompiled_code = ""
        self.dotnet_types = []  # Namespace/Class/Method listesi (string satirlari)
        # Risk skoru (0-100) ve seviyesi (Dusuk/Orta/Yuksek/Kritik)
        self.risk_score = 0
        self.risk_level = "Dusuk"
        self.risk_color = "#4CAF50"
        self.risk_breakdown = []
        # Win API sekmesi icin gruplu / kategorize edilmis API listesi
        # {sistem_kategorisi: [(dll, fonksiyon, supheli_mi, supheli_kategori), ...]}
        self.winapi_groups = {}
        self.winapi_total_count = 0
        self.winapi_suspicious_count = 0


def compute_hashes(filepath):
    """MD5 ve SHA256 hesapla."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def detect_dotnet(pe):
    """
    .NET Assembly tespiti:
    - CLR header (COM Descriptor Directory) varligi
    - mscoree.dll import edilmis mi
    - _CorDllMain / _CorExeMain entry point mi
    """
    reasons = []
    is_dotnet = False

    # 1) CLR / COM Descriptor Directory kontrolu (en guvenilir yontem)
    try:
        clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        ]
        if clr_dir.VirtualAddress != 0 and clr_dir.Size != 0:
            is_dotnet = True
            reasons.append("CLR metadata (COM Descriptor Directory) bulundu")
    except (IndexError, AttributeError):
        pass

    # 2) mscoree.dll import kontrolu
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="ignore").lower()
                if dll_name == "mscoree.dll":
                    is_dotnet = True
                    reasons.append("mscoree.dll import edilmis")
                    for imp in entry.imports:
                        if imp.name and imp.name.decode(errors="ignore") in ("_CorDllMain", "_CorExeMain"):
                            reasons.append(f"{imp.name.decode()} entry point bulundu")
    except Exception:
        pass

    return is_dotnet, reasons


def get_compiler_info(pe):
    """Basit sezgisel derleyici tespiti (linker versiyonu / rich header)."""
    try:
        major = pe.OPTIONAL_HEADER.MajorLinkerVersion
        minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
        return f"Linker v{major}.{minor}"
    except Exception:
        return "Bilinmiyor"


def analyze_pe_info(result, pe, filepath):
    """PE Info sekmesi icin genel bilgileri doldur."""
    size = os.path.getsize(filepath)
    md5, sha256 = compute_hashes(filepath)

    arch = "x64" if pe.FILE_HEADER.Machine == 0x8664 else (
        "x86" if pe.FILE_HEADER.Machine == 0x14c else hex(pe.FILE_HEADER.Machine)
    )

    result.info["Dosya Adi"] = result.filename
    result.info["Yol"] = filepath
    result.info["Boyut"] = f"{size:,} bayt ({size/1024:.1f} KB)"
    result.info["MD5"] = md5
    result.info["SHA256"] = sha256
    result.info["Mimari"] = arch
    result.info["Entry Point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    result.info["Image Base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
    result.info["Compiler"] = get_compiler_info(pe)
    result.info["Zaman Damgasi"] = str(
        datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)
    ) + " UTC"
    result.info["Subsystem"] = str(pe.OPTIONAL_HEADER.Subsystem)
    result.info["DLL mi?"] = "Evet" if pe.FILE_HEADER.Characteristics & 0x2000 else "Hayir (EXE)"

    # Section listesi
    sections = []
    for sec in pe.sections:
        name = sec.Name.decode(errors="ignore").strip("\x00")
        sections.append({
            "Ad": name,
            "VirtualAddress": hex(sec.VirtualAddress),
            "VirtualSize": hex(sec.Misc_VirtualSize),
            "RawSize": hex(sec.SizeOfRawData),
            "Entropy": f"{sec.get_entropy():.2f}",
        })
    result.info["_sections"] = sections


def _match_suspicious_category(fname):
    """Bir API adinin hangi supheli kategoriye girdigini dondurur (yoksa None)."""
    for category, api_names in SUSPICIOUS_APIS.items():
        for api in api_names:
            if fname.lower().startswith(api.lower()):
                return category
    return None


def analyze_imports(result, pe):
    """Imports sekmesi + supheli API taramasi + Win API gruplama."""
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors="ignore")
        dll_key = dll_name.lower()
        func_list = []

        # Win API sekmesi icin sistem kategorisini belirle
        sys_category = WINAPI_DLL_CATEGORIES.get(dll_key, "Diger / Uygulamaya Ozel DLL")

        for imp in entry.imports:
            fname = imp.name.decode(errors="ignore") if imp.name else f"Ordinal_{imp.ordinal}"
            func_list.append(fname)

            # Supheli API kontrolu
            sus_category = _match_suspicious_category(fname)
            if sus_category:
                result.suspicious_hits.setdefault(sus_category, []).append((dll_name, fname))

            # Win API sekmesi icin kayit tut (tum sistem API cagrilari, supheli olsun olmasin)
            result.winapi_groups.setdefault(sys_category, []).append(
                (dll_name, fname, sus_category is not None, sus_category)
            )
            result.winapi_total_count += 1
            if sus_category:
                result.winapi_suspicious_count += 1

        result.imports[dll_name] = sorted(func_list)


def analyze_exports(result, pe):
    """Exports sekmesi."""
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode(errors="ignore") if exp.name else f"Ordinal_{exp.ordinal}"
        result.exports.append(f"{name}  (RVA: {hex(exp.address)})")


def extract_strings(data, min_len, encoding="ascii"):
    """Basit string cikarma (ASCII veya UTF-16LE)."""
    results = []
    if encoding == "ascii":
        pattern = re.compile(b"[\x20-\x7e]{%d,}" % min_len)
        for m in pattern.finditer(data):
            results.append(m.group().decode("ascii", errors="ignore"))
    else:  # utf-16
        pattern = re.compile(b"(?:[\x20-\x7e]\x00){%d,}" % min_len)
        for m in pattern.finditer(data):
            try:
                results.append(m.group().decode("utf-16-le", errors="ignore"))
            except Exception:
                pass
    return results


def analyze_strings(result, filepath):
    """Strings sekmesi: ASCII + Unicode + filtrelenmis kategoriler."""
    with open(filepath, "rb") as f:
        data = f.read()

    result.ascii_strings = extract_strings(data, ASCII_MIN_LEN, "ascii")
    result.unicode_strings = extract_strings(data, UNICODE_MIN_LEN, "utf16")

    # Filtreler (tum ham veri uzerinde regex ile).
    # Tum desenler non-capturing group kullandigi icin findall() artik
    # sadece bytes objeleri donduruyor -> guvenle .decode() cagrilabiliyor.
    # (Onceki hata: capturing group -> findall() tuple donduruyordu ->
    #  'tuple' object has no attribute 'decode')
    result.filtered["url"] = sorted(set(m.decode(errors="ignore") for m in RE_URL.findall(data)))
    result.filtered["ip"] = sorted(set(m.decode(errors="ignore") for m in RE_IP.findall(data)))
    result.filtered["registry"] = sorted(set(m.decode(errors="ignore") for m in RE_REGISTRY.findall(data)))
    result.filtered["filepath"] = sorted(set(m.decode(errors="ignore") for m in RE_FILEPATH.findall(data)))
    result.filtered["cmdline"] = sorted(set(m.decode(errors="ignore") for m in RE_CMDLINE.findall(data)))


def disassemble_text_section(result, pe):
    """
    Capstone kullanarak .text bolumunu ve entry point'i disassemble eder.
    x86/x64 otomatik secilir.
    """
    try:
        text_section = None
        for sec in pe.sections:
            name = sec.Name.decode(errors="ignore").strip("\x00")
            if name == ".text":
                text_section = sec
                break

        if text_section is None:
            result.disasm_lines.append("(.text bolumu bulunamadi)")
            return

        code = text_section.get_data()
        base_addr = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress

        if pe.FILE_HEADER.Machine == 0x8664:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

        md.detail = False

        # Cok buyuk bolumlerde performans icin ilk ~4000 instruction ile sinirla
        max_instructions = 4000
        count = 0
        for insn in md.disasm(code, base_addr):
            line = f"{insn.address:08x}:    {insn.mnemonic}\t{insn.op_str}"
            result.disasm_lines.append(line)
            count += 1
            if count >= max_instructions:
                result.disasm_lines.append("... (cikti sinirlandirildi, ilk 4000 instruction gosteriliyor)")
                break

        if count == 0:
            result.disasm_lines.append("(Disassemble edilecek instruction bulunamadi)")

    except Exception as e:
        result.disasm_lines.append(f"Disassembly hatasi: {e}")


def find_ilspycmd():
    """Sistemde ilspycmd kurulu mu kontrol et."""
    for candidate in ("ilspycmd", "ilspycmd.exe"):
        try:
            proc = subprocess.run(
                [candidate, "--version"],
                capture_output=True, text=True, timeout=10
            )
            if proc.returncode == 0 or proc.stdout or proc.stderr:
                return candidate
        except (FileNotFoundError, OSError):
            continue
        except Exception:
            continue
    return None


def decompile_dotnet(result, filepath):
    """
    .NET dosyasini ilspycmd ile decompile eder.
    ilspycmd bulunamazsa kullaniciya bilgi mesaji verir.
    """
    tool = find_ilspycmd()
    if not tool:
        result.decompiled_code = (
            "[!] ilspycmd sistemde bulunamadi.\n\n"
            "Gercek C# kodunu gormek icin kurun:\n"
            "    dotnet tool install -g ilspycmd\n\n"
            "Kurulumdan sonra PATH'e eklendiginden emin olun ve dosyayi tekrar acin."
        )
        return

    try:
        proc = subprocess.run(
            [tool, filepath],
            capture_output=True, text=True, timeout=120
        )
        if proc.returncode == 0 and proc.stdout.strip():
            result.decompiled_code = proc.stdout
            # Namespace / class / method listesini basit regex ile cikar
            extract_dotnet_symbols(result, proc.stdout)
        else:
            result.decompiled_code = (
                "[!] ilspycmd calisti fakat cikti alinamadi.\n\n"
                f"stderr:\n{proc.stderr}"
            )
    except subprocess.TimeoutExpired:
        result.decompiled_code = "[!] ilspycmd zaman asimina ugradi (120sn)."
    except Exception as e:
        result.decompiled_code = f"[!] Decompile hatasi: {e}"


def extract_dotnet_symbols(result, decompiled_source):
    """Decompile edilmis C# kaynagindan namespace/class/method isimlerini cikarir."""
    ns_pattern = re.compile(r"^\s*namespace\s+([A-Za-z0-9_.]+)", re.MULTILINE)
    class_pattern = re.compile(
        r"^\s*(?:public|private|internal|protected)?\s*(?:static\s+|sealed\s+|abstract\s+)*class\s+([A-Za-z0-9_<>]+)",
        re.MULTILINE
    )
    method_pattern = re.compile(
        r"^\s*(?:public|private|internal|protected)\s+(?:static\s+|virtual\s+|override\s+|async\s+)*"
        r"[\w<>\[\],\s]+?\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*\)\s*\{",
        re.MULTILINE
    )

    for m in ns_pattern.finditer(decompiled_source):
        result.dotnet_types.append(f"[Namespace] {m.group(1)}")
    for m in class_pattern.finditer(decompiled_source):
        result.dotnet_types.append(f"[Class] {m.group(1)}")
    for m in method_pattern.finditer(decompiled_source):
        result.dotnet_types.append(f"[Method] {m.group(1)}")


# Risk agirlik tablosu: kategori -> her isabet basina puan
RISK_WEIGHTS = {
    "Process / Injection": 14,
    "Keyboard / Input (Keylogger)": 12,
    "Network": 6,
    "Screen / Capture": 8,
    "Registry": 5,
    "Anti-Debug / Evasion": 7,
    "Persistence / Service": 10,
    "Crypto / Packer": 4,
}


def compute_risk_score(result):
    """
    Supheli API bulgularina, section entropisine ve diger sinyallere
    dayanarak 0-100 arasi bir risk skoru ve seviyesi hesaplar.
    Bu bir imza/AV motoru degildir, sadece sezgisel bir gostergedir.
    """
    score = 0
    breakdown = []

    # 1) Kategori bazli supheli API puanlari
    for category, hits in result.suspicious_hits.items():
        unique_hits = set(hits)
        weight = RISK_WEIGHTS.get(category, 5)
        cat_score = weight + min(len(unique_hits) - 1, 5) * 2
        score += cat_score
        breakdown.append((f"Supheli API: {category}", cat_score))

    # 2) Yuksek entropi section kontrolu (paketlenmis/sifrelenmis olabilir, >=7.2 supheli)
    high_entropy_sections = []
    for sec in result.info.get("_sections", []):
        try:
            ent = float(sec["Entropy"])
        except (ValueError, KeyError):
            continue
        if ent >= 7.2:
            high_entropy_sections.append(sec["Ad"])
    if high_entropy_sections:
        bonus = min(len(high_entropy_sections) * 8, 20)
        score += bonus
        breakdown.append((f"Yuksek entropili section(lar): {', '.join(high_entropy_sections)}", bonus))

    # 3) Supheli komut satiri / URL / IP gibi string bulgulari
    if result.filtered.get("cmdline"):
        score += 6
        breakdown.append(("Supheli komut satiri ifadeleri bulundu", 6))
    if result.filtered.get("url"):
        score += 3
        breakdown.append(("URL stringleri bulundu", 3))
    if result.filtered.get("ip"):
        score += 3
        breakdown.append(("IP adresi stringleri bulundu", 3))

    # 4) Az import + export yoklugu (packer belirtisi olabilir) - hafif sinyal
    if not result.exports and len(result.imports) <= 2 and result.is_native_pe:
        score += 5
        breakdown.append(("Cok az import / export (paketlenmis olabilir)", 5))

    score = max(0, min(100, score))

    if score < 20:
        level, color = "Dusuk", "#4CAF50"       # yesil
    elif score < 45:
        level, color = "Orta", "#FFC107"        # sari
    elif score < 70:
        level, color = "Yuksek", "#FF9800"      # turuncu
    else:
        level, color = "Kritik", "#F44336"      # kirmizi

    result.risk_score = score
    result.risk_level = level
    result.risk_color = color
    result.risk_breakdown = breakdown


def run_full_analysis(filepath):
    """
    Ana analiz fonksiyonu. Bir AnalysisResult dondurur.
    Hata durumunda result.error doldurulur, exception firlatilmaz
    (gereksinim: bozuk dosya uygulamayi kapatmamali).
    """
    result = AnalysisResult(filepath)

    try:
        pe = pefile.PE(filepath, fast_load=False)
    except pefile.PEFormatError as e:
        result.error = f"Gecersiz veya bozuk PE dosyasi: {e}"
        return result
    except FileNotFoundError:
        result.error = "Dosya bulunamadi."
        return result
    except Exception as e:
        result.error = f"Dosya acilirken beklenmeyen hata: {e}"
        return result

    try:
        # 1) .NET / Native tespiti
        is_dotnet, reasons = detect_dotnet(pe)
        result.is_dotnet = is_dotnet
        result.is_native_pe = not is_dotnet
        result.info["_dotnet_reasons"] = reasons

        # 2) Ortak PE bilgisi (her iki turde de gosterilir)
        analyze_pe_info(result, pe, filepath)
        analyze_imports(result, pe)
        analyze_exports(result, pe)
        analyze_strings(result, filepath)

        if is_dotnet:
            # .NET dosyayi native gibi disassemble ETMEYIZ (gereksinim #9)
            result.disasm_lines.append(
                "Bu dosya bir .NET Assembly. Native disassembly yerine "
                "'Decompiled C#' sekmesindeki kaynak koda bakiniz."
            )
            decompile_dotnet(result, filepath)
        else:
            # Native PE -> disassembly yap
            disassemble_text_section(result, pe)

        # Risk skoru her iki tur icin de hesaplanir
        compute_risk_score(result)

        pe.close()

    except Exception as e:
        result.error = f"Analiz sirasinda hata: {e}\n{traceback.format_exc()}"

    return result


# ===========================================================================
# GUI  --  FOX DLL Explorer
# ===========================================================================
#
# Tasarim notlari:
#  - Sol tarafta sabit bir "Sidebar" (dosya bilgisi ozeti + risk gostergesi)
#  - Sag tarafta sekmeli detay paneli
#  - Ust kisimda baslik + dosya ac butonu + hizli rozetler (.NET/Native, Mimari)
#  - Risk skoru: renkli daire/bar + puan + seviye etiketi (Dusuk/Orta/Yuksek/Kritik)
#  - Supheli API kategorileri kart (chip) seklinde renkli etiketlerle gosterilir
#  - Yeni: "🛡 Win API" sekmesi - tum Windows API cagrilarini sistem
#    kategorisine (Cekirdek, Ag, Registry, UI, vb.) gore gruplayip
#    supheli olanlari isaretler
#  - Karanlik, kontrastli renk paleti; monospace font analiz iceriklerinde
#
# ===========================================================================

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ---------------------------------------------------------------------------
# Renk paleti (tek yerden yonetim icin)
# ---------------------------------------------------------------------------
PALETTE = {
    "bg_main": "#0f1117",
    "bg_panel": "#161923",
    "bg_card": "#1c2030",
    "bg_card_alt": "#20263a",
    "accent": "#ff7a1a",       # FOX turuncu vurgusu
    "accent_soft": "#ffb066",
    "text_primary": "#eef1f8",
    "text_secondary": "#9aa3b8",
    "border": "#2a3044",
    "success": "#4CAF50",
    "warning": "#FFC107",
    "danger_high": "#FF9800",
    "danger_critical": "#F44336",
    "dotnet": "#4FC3F7",
    "native": "#81C784",
}

FONT_MONO = ("Consolas", 13)
FONT_MONO_SMALL = ("Consolas", 12)


class RiskGauge(ctk.CTkFrame):
    """Basit dairesel risk gostergesi: Canvas ile cizilen yay + ortada puan/etiket."""

    def __init__(self, parent, size=150, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.size = size
        self.canvas = tk.Canvas(
            self, width=size, height=size,
            bg=PALETTE["bg_panel"], highlightthickness=0
        )
        self.canvas.pack()
        self.set_value(0, "Dusuk", PALETTE["success"])

    def set_value(self, score, level, color):
        self.canvas.delete("all")
        pad = 10
        x0, y0 = pad, pad
        x1, y1 = self.size - pad, self.size - pad

        # Arka plan halkasi (gri)
        self.canvas.create_arc(
            x0, y0, x1, y1, start=90, extent=-360,
            style="arc", outline=PALETTE["border"], width=14
        )
        # Deger halkasi
        extent = -360 * (score / 100)
        self.canvas.create_arc(
            x0, y0, x1, y1, start=90, extent=extent,
            style="arc", outline=color, width=14
        )
        # Orta yazi
        self.canvas.create_text(
            self.size / 2, self.size / 2 - 8,
            text=f"{score}", fill=PALETTE["text_primary"],
            font=("Segoe UI", 26, "bold")
        )
        self.canvas.create_text(
            self.size / 2, self.size / 2 + 20,
            text=level.upper(), fill=color,
            font=("Segoe UI", 12, "bold")
        )


class Chip(ctk.CTkLabel):
    """Kucuk, renkli 'etiket/rozet' bileseni (kategori chip'leri icin)."""

    def __init__(self, parent, text, color, **kwargs):
        super().__init__(
            parent, text=text,
            fg_color=color, text_color="#101010",
            corner_radius=10, font=("Segoe UI", 11, "bold"),
            padx=10, pady=4, **kwargs
        )


class FoxDLLExplorer(ctk.CTk):
    """FOX DLL Explorer ana pencere sinifi."""

    def __init__(self):
        super().__init__()

        self.title("🦊 FOX DLL Explorer")
        self.geometry("1400x840")
        self.minsize(1100, 660)
        self.configure(fg_color=PALETTE["bg_main"])

        self.current_result = None

        self._build_header()
        self._build_body()          # sidebar + tabview yan yana
        self._build_statusbar()

    # ------------------------------------------------------------------
    # UST BASLIK
    # ------------------------------------------------------------------
    def _build_header(self):
        header = ctk.CTkFrame(self, height=72, corner_radius=0, fg_color=PALETTE["bg_panel"])
        header.pack(side="top", fill="x")
        header.pack_propagate(False)

        logo_frame = ctk.CTkFrame(header, fg_color="transparent")
        logo_frame.pack(side="left", padx=20)

        ctk.CTkLabel(
            logo_frame, text="🦊", font=("Segoe UI Emoji", 28)
        ).pack(side="left", padx=(0, 10))

        title_box = ctk.CTkFrame(logo_frame, fg_color="transparent")
        title_box.pack(side="left")
        ctk.CTkLabel(
            title_box, text="FOX DLL Explorer",
            font=("Segoe UI", 20, "bold"), text_color=PALETTE["text_primary"]
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_box, text="PE / .NET Analiz Araci",
            font=("Segoe UI", 11), text_color=PALETTE["text_secondary"]
        ).pack(anchor="w")

        # Sag taraf: rozetler + dosya ac butonu
        right_box = ctk.CTkFrame(header, fg_color="transparent")
        right_box.pack(side="right", padx=20)

        self.open_btn = ctk.CTkButton(
            right_box, text="📂  Dosya Ac", width=150, height=38,
            fg_color=PALETTE["accent"], hover_color="#e0660a",
            font=("Segoe UI", 13, "bold"), corner_radius=10,
            command=self.open_file_dialog
        )
        self.open_btn.pack(side="right", padx=(12, 0))

        self.save_btn = ctk.CTkButton(
            right_box, text="💾  Raporu Kaydet (.txt)", width=190, height=38,
            fg_color=PALETTE["bg_card"], hover_color=PALETTE["bg_card_alt"],
            text_color=PALETTE["text_primary"],
            font=("Segoe UI", 13, "bold"), corner_radius=10,
            state="disabled",
            command=self.save_report
        )
        self.save_btn.pack(side="right", padx=(12, 0))

        self.arch_badge = ctk.CTkLabel(
            right_box, text="", font=("Segoe UI", 12, "bold"),
            fg_color=PALETTE["bg_card"], corner_radius=8, padx=12, pady=6
        )
        self.arch_badge.pack(side="right", padx=6)

        self.filetype_badge = ctk.CTkLabel(
            right_box, text="Dosya bekleniyor...", font=("Segoe UI", 12, "bold"),
            fg_color=PALETTE["bg_card"], corner_radius=8, padx=12, pady=6
        )
        self.filetype_badge.pack(side="right", padx=6)

    # ------------------------------------------------------------------
    # GOVDE: SIDEBAR (ozet + risk) + TABVIEW (detaylar)
    # ------------------------------------------------------------------
    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color=PALETTE["bg_main"])
        body.pack(fill="both", expand=True, padx=14, pady=12)

        # --- SIDEBAR -----------------------------------------------------
        self.sidebar = ctk.CTkScrollableFrame(
            body, width=290, fg_color=PALETTE["bg_panel"], corner_radius=14
        )
        self.sidebar.pack(side="left", fill="y", padx=(0, 12))

        self._build_sidebar_placeholder()

        # --- SAG PANEL: TABVIEW -------------------------------------------
        right_panel = ctk.CTkFrame(body, fg_color="transparent")
        right_panel.pack(side="left", fill="both", expand=True)

        self.tabview = ctk.CTkTabview(
            right_panel, fg_color=PALETTE["bg_panel"], corner_radius=14,
            segmented_button_selected_color=PALETTE["accent"],
            segmented_button_selected_hover_color="#e0660a",
            segmented_button_unselected_color=PALETTE["bg_card"],
        )
        self.tabview.pack(fill="both", expand=True)

        self.tab_info = self.tabview.add("📦 PE Info")
        self.tab_imports = self.tabview.add("📥 Imports")
        self.tab_winapi = self.tabview.add("🛡 Win API")
        self.tab_exports = self.tabview.add("📤 Exports")
        self.tab_strings = self.tabview.add("📝 Strings")
        self.tab_asm = self.tabview.add("⚙ Assembly")
        self.tab_decompile = self.tabview.add("💻 Decompiled C#")
        self.tab_suspicious = self.tabview.add("🚨 Supheli API")

        self._build_info_tab()
        self._build_imports_tab()
        self._build_winapi_tab()
        self._build_exports_tab()
        self._build_strings_tab()
        self._build_asm_tab()
        self._build_decompile_tab()
        self._build_suspicious_tab()

    def _build_sidebar_placeholder(self):
        """Analiz baslamadan once sidebar'da gosterilen bos durum."""
        for w in self.sidebar.winfo_children():
            w.destroy()

        ctk.CTkLabel(
            self.sidebar, text="🦊", font=("Segoe UI Emoji", 42)
        ).pack(pady=(30, 10))
        ctk.CTkLabel(
            self.sidebar, text="Henuz dosya analiz edilmedi",
            font=("Segoe UI", 13, "bold"), text_color=PALETTE["text_secondary"],
            wraplength=230, justify="center"
        ).pack(pady=(0, 6))
        ctk.CTkLabel(
            self.sidebar, text="Baslamak icin sag ustten\nbir DLL/EXE dosyasi acin.",
            font=("Segoe UI", 11), text_color=PALETTE["text_secondary"],
            wraplength=230, justify="center"
        ).pack()

    def _card(self, parent, title=None):
        """Sidebar icinde kullanilan standart 'kart' konteyneri olusturur."""
        card = ctk.CTkFrame(parent, fg_color=PALETTE["bg_card"], corner_radius=12)
        card.pack(fill="x", padx=14, pady=8)
        if title:
            ctk.CTkLabel(
                card, text=title, font=("Segoe UI", 12, "bold"),
                text_color=PALETTE["text_secondary"]
            ).pack(anchor="w", padx=14, pady=(10, 0))
        return card

    def _build_sidebar_content(self, result):
        """Analiz sonrasi sidebar'i dosya ozeti + risk gostergesiyle doldurur."""
        for w in self.sidebar.winfo_children():
            w.destroy()

        # --- Dosya adi basligi ---
        header_card = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        header_card.pack(fill="x", padx=14, pady=(16, 4))
        ctk.CTkLabel(
            header_card, text=result.filename, font=("Segoe UI", 15, "bold"),
            text_color=PALETTE["text_primary"], wraplength=250, justify="left"
        ).pack(anchor="w")

        type_text = ".NET Assembly" if result.is_dotnet else "Native PE (C/C++)"
        type_color = PALETTE["dotnet"] if result.is_dotnet else PALETTE["native"]
        ctk.CTkLabel(
            header_card, text=type_text, font=("Segoe UI", 12, "bold"),
            text_color=type_color
        ).pack(anchor="w", pady=(2, 0))

        # --- RISK GOSTERGESI ---
        risk_card = self._card(self.sidebar, "TEHLIKE ORANI")
        gauge_wrap = ctk.CTkFrame(risk_card, fg_color="transparent")
        gauge_wrap.pack(pady=8)
        gauge = RiskGauge(gauge_wrap, size=150)
        gauge.pack()
        gauge.set_value(result.risk_score, result.risk_level, result.risk_color)

        ctk.CTkLabel(
            risk_card, text=f"Risk Seviyesi: {result.risk_level}",
            font=("Segoe UI", 13, "bold"), text_color=result.risk_color
        ).pack(pady=(0, 4))

        bar = ctk.CTkProgressBar(
            risk_card, progress_color=result.risk_color,
            fg_color=PALETTE["bg_card_alt"], height=10, corner_radius=6
        )
        bar.pack(fill="x", padx=16, pady=(0, 4))
        bar.set(result.risk_score / 100)

        ctk.CTkLabel(
            risk_card, text=f"{result.risk_score} / 100 puan",
            font=("Segoe UI", 11), text_color=PALETTE["text_secondary"]
        ).pack(pady=(0, 12))

        # Risk gerekcesi (kisa liste)
        if result.risk_breakdown:
            reasons_card = self._card(self.sidebar, "RISK GEREKCESI")
            for reason, pts in result.risk_breakdown[:8]:
                row = ctk.CTkFrame(reasons_card, fg_color="transparent")
                row.pack(fill="x", padx=14, pady=3)
                ctk.CTkLabel(
                    row, text=f"• {reason}", font=("Segoe UI", 11),
                    text_color=PALETTE["text_primary"], wraplength=180,
                    justify="left", anchor="w"
                ).pack(side="left", fill="x", expand=True)
                ctk.CTkLabel(
                    row, text=f"+{pts}", font=("Segoe UI", 11, "bold"),
                    text_color=result.risk_color
                ).pack(side="right")
            ctk.CTkLabel(reasons_card, text="", height=4).pack()
        else:
            reasons_card = self._card(self.sidebar)
            ctk.CTkLabel(
                reasons_card, text="✅ Belirgin bir risk sinyali bulunamadi.",
                font=("Segoe UI", 11), text_color=PALETTE["success"],
                wraplength=230, justify="left"
            ).pack(padx=14, pady=12)

        # --- SUPHELI API KATEGORI CHIPLERI ---
        if result.suspicious_hits:
            chip_card = self._card(self.sidebar, "SUPHELI KATEGORILER")
            chip_wrap = ctk.CTkFrame(chip_card, fg_color="transparent")
            chip_wrap.pack(fill="x", padx=12, pady=(6, 14))

            cat_colors = {
                "Process / Injection": PALETTE["danger_critical"],
                "Keyboard / Input (Keylogger)": PALETTE["danger_high"],
                "Network": PALETTE["warning"],
                "Screen / Capture": PALETTE["warning"],
                "Registry": PALETTE["accent_soft"],
                "Anti-Debug / Evasion": PALETTE["danger_high"],
                "Persistence / Service": PALETTE["danger_critical"],
                "Crypto / Packer": PALETTE["accent_soft"],
            }
            row = None
            for i, category in enumerate(result.suspicious_hits.keys()):
                if i % 2 == 0:
                    row = ctk.CTkFrame(chip_wrap, fg_color="transparent")
                    row.pack(fill="x", pady=3)
                short = category.split(" / ")[0].split(" (")[0]
                chip = Chip(row, short, cat_colors.get(category, PALETTE["accent_soft"]))
                chip.pack(side="left", padx=3)

        # --- HIZLI OZET BILGILER ---
        quick_card = self._card(self.sidebar, "HIZLI OZET")
        quick_rows = [
            ("Boyut", result.info.get("Boyut", "-")),
            ("Mimari", result.info.get("Mimari", "-")),
            ("Import DLL", str(len(result.imports))),
            ("Win API cagrisi", str(result.winapi_total_count)),
            ("Export", str(len(result.exports))),
        ]
        for label, val in quick_rows:
            row = ctk.CTkFrame(quick_card, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=3)
            ctk.CTkLabel(
                row, text=label, font=("Segoe UI", 11),
                text_color=PALETTE["text_secondary"]
            ).pack(side="left")
            ctk.CTkLabel(
                row, text=val, font=("Segoe UI", 11, "bold"),
                text_color=PALETTE["text_primary"]
            ).pack(side="right")
        ctk.CTkLabel(quick_card, text="", height=4).pack()

        # --- HASH bilgisi ---
        hash_card = self._card(self.sidebar, "HASH")
        for label in ("MD5", "SHA256"):
            val = result.info.get(label, "-")
            ctk.CTkLabel(
                hash_card, text=label, font=("Segoe UI", 10, "bold"),
                text_color=PALETTE["text_secondary"]
            ).pack(anchor="w", padx=14, pady=(8, 0))
            ctk.CTkLabel(
                hash_card, text=val, font=("Consolas", 10),
                text_color=PALETTE["text_primary"], wraplength=250, justify="left"
            ).pack(anchor="w", padx=14, pady=(0, 4))
        ctk.CTkLabel(hash_card, text="", height=4).pack()

    # ------------------------------------------------------------------
    # SEKME ICERIKLERI (textbox olusturma yardimcisi)
    # ------------------------------------------------------------------
    def _make_textbox(self, parent, font=FONT_MONO):
        box = ctk.CTkTextbox(
            parent, font=font, fg_color=PALETTE["bg_card"],
            text_color=PALETTE["text_primary"], corner_radius=10,
            border_width=1, border_color=PALETTE["border"]
        )
        box.pack(fill="both", expand=True, padx=10, pady=10)
        box.configure(state="disabled")
        return box

    def _build_info_tab(self):
        self.info_box = self._make_textbox(self.tab_info)

    def _build_imports_tab(self):
        self.imports_box = self._make_textbox(self.tab_imports)

    def _build_winapi_tab(self):
        """
        🛡 Win API sekmesi:
        Tum Windows API cagrilarini sistem kategorisine (Cekirdek, Ag, UI,
        Registry, Kriptografi, vb.) gore gruplar ve supheli olanlari
        kirmizi/turuncu isaretlerle vurgular. Ustte filtre + ozet sayaci var.
        """
        top = ctk.CTkFrame(self.tab_winapi, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(
            top, text="🛡 Filtre:", font=("Segoe UI", 12, "bold"),
            text_color=PALETTE["text_secondary"]
        ).pack(side="left", padx=(4, 10))

        self.winapi_filter_var = ctk.StringVar(value="Tumu")
        options = ["Tumu", "Sadece Supheli Olanlar"]
        self.winapi_filter_menu = ctk.CTkOptionMenu(
            top, values=options, variable=self.winapi_filter_var,
            command=lambda _=None: self.render_winapi_tab(),
            fg_color=PALETTE["bg_card"], button_color=PALETTE["accent"],
            button_hover_color="#e0660a", dropdown_fg_color=PALETTE["bg_card"],
            width=200
        )
        self.winapi_filter_menu.pack(side="left", padx=4)

        self.winapi_summary_lbl = ctk.CTkLabel(
            top, text="", font=("Segoe UI", 12, "bold"), text_color=PALETTE["text_secondary"]
        )
        self.winapi_summary_lbl.pack(side="right", padx=10)

        self.winapi_box = self._make_textbox(self.tab_winapi, font=FONT_MONO_SMALL)

    def _build_exports_tab(self):
        self.exports_box = self._make_textbox(self.tab_exports)

    def _build_strings_tab(self):
        filt_frame = ctk.CTkFrame(self.tab_strings, fg_color="transparent")
        filt_frame.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(
            filt_frame, text="🔍 Filtre:", font=("Segoe UI", 12, "bold"),
            text_color=PALETTE["text_secondary"]
        ).pack(side="left", padx=(4, 10))

        self.string_filter_var = ctk.StringVar(value="Tumu")
        options = ["Tumu", "ASCII", "Unicode", "URL", "IP Adresleri", "Registry", "Dosya Yollari", "Komut Satirlari"]
        self.string_filter_menu = ctk.CTkOptionMenu(
            filt_frame, values=options, variable=self.string_filter_var,
            command=lambda _=None: self.render_strings_tab(),
            fg_color=PALETTE["bg_card"], button_color=PALETTE["accent"],
            button_hover_color="#e0660a", dropdown_fg_color=PALETTE["bg_card"],
            width=170
        )
        self.string_filter_menu.pack(side="left", padx=4)

        self.strings_box = self._make_textbox(self.tab_strings, font=FONT_MONO_SMALL)

    def _build_asm_tab(self):
        self.asm_box = self._make_textbox(self.tab_asm)

    def _build_decompile_tab(self):
        self.decompile_box = self._make_textbox(self.tab_decompile)

    def _build_suspicious_tab(self):
        self.suspicious_box = self._make_textbox(self.tab_suspicious)

    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, height=34, corner_radius=0, fg_color=PALETTE["bg_panel"])
        bar.pack(side="bottom", fill="x")
        self.status_lbl = ctk.CTkLabel(
            bar, text="🦊 Hazir. Analiz icin bir DLL/EXE dosyasi acin.",
            anchor="w", font=("Segoe UI", 11), text_color=PALETTE["text_secondary"]
        )
        self.status_lbl.pack(side="left", padx=14, pady=6)

        self.progress = ctk.CTkProgressBar(
            bar, width=160, height=8, progress_color=PALETTE["accent"],
            fg_color=PALETTE["bg_card"], mode="indeterminate"
        )
        self.progress.pack(side="right", padx=14, pady=8)
        self.progress.set(0)

    # ------------------------------------------------------------------
    # DOSYA ACMA / ANALIZ TETIKLEME
    # ------------------------------------------------------------------
    def open_file_dialog(self):
        filepath = filedialog.askopenfilename(
            title="DLL/EXE dosyasi sec",
            filetypes=[("Executable files", "*.dll *.exe *.ocx *.sys"), ("Tum dosyalar", "*.*")]
        )
        if not filepath:
            return
        self.start_analysis(filepath)

    def start_analysis(self, filepath):
        self.status_lbl.configure(text=f"⏳ Analiz ediliyor: {os.path.basename(filepath)} ...")
        self.filetype_badge.configure(text="Analiz ediliyor...", fg_color=PALETTE["bg_card"])
        self.arch_badge.configure(text="")
        self.open_btn.configure(state="disabled")
        self.save_btn.configure(state="disabled")
        self.progress.start()
        self._clear_all_tabs()
        self._build_sidebar_placeholder()

        thread = threading.Thread(target=self._analysis_worker, args=(filepath,), daemon=True)
        thread.start()

    def _analysis_worker(self, filepath):
        # Analiz motoru kendi ici try/except ile korunuyor; burada da ekstra
        # bir guvenlik agi var ki GUI thread'i asla beklenmedik bir istisnayla
        # cokup uygulamayi kapatmasin (gereksinim #9).
        try:
            result = run_full_analysis(filepath)
        except Exception as e:
            result = AnalysisResult(filepath)
            result.error = f"Beklenmeyen kritik hata: {e}\n{traceback.format_exc()}"
        self.after(0, self._on_analysis_done, result)

    def _on_analysis_done(self, result):
        self.current_result = result
        self.progress.stop()
        self.progress.set(0)
        self.open_btn.configure(state="normal")

        if result.error:
            self.filetype_badge.configure(text="❌ Hata", fg_color=PALETTE["danger_critical"])
            self.status_lbl.configure(text=f"Hata: {result.error.splitlines()[0]}")
            self.save_btn.configure(state="disabled")
            messagebox.showerror("Analiz Hatasi", result.error)
            return

        if result.is_dotnet:
            self.filetype_badge.configure(
                text="🟦 .NET Assembly", fg_color=PALETTE["bg_card"], text_color=PALETTE["dotnet"]
            )
        else:
            self.filetype_badge.configure(
                text="🟩 Native PE (C/C++)", fg_color=PALETTE["bg_card"], text_color=PALETTE["native"]
            )
        self.arch_badge.configure(
            text=result.info.get("Mimari", "-"), text_color=PALETTE["text_primary"]
        )

        self._build_sidebar_content(result)

        self.render_info_tab()
        self.render_imports_tab()
        self.render_winapi_tab()
        self.render_exports_tab()
        self.render_strings_tab()
        self.render_asm_tab()
        self.render_decompile_tab()
        self.render_suspicious_tab()

        risk_emoji = {"Dusuk": "🟢", "Orta": "🟡", "Yuksek": "🟠", "Kritik": "🔴"}.get(result.risk_level, "")
        self.status_lbl.configure(
            text=f"✅ Tamamlandi: {result.filename}   |   {risk_emoji} Risk: {result.risk_level} "
                 f"({result.risk_score}/100)"
        )

        # Kritik/Yuksek riskte otomatik olarak Supheli API sekmesine gec
        if result.risk_level in ("Kritik", "Yuksek") and result.suspicious_hits:
            self.tabview.set("🚨 Supheli API")

        self.save_btn.configure(state="normal")

    def _clear_all_tabs(self):
        for box in (self.info_box, self.imports_box, self.winapi_box, self.exports_box,
                    self.strings_box, self.asm_box, self.decompile_box, self.suspicious_box):
            box.configure(state="normal")
            box.delete("1.0", "end")
            box.configure(state="disabled")

    # ------------------------------------------------------------------
    # RAPORU .TXT OLARAK KAYDET (tum bulgular tek dosyada)
    # ------------------------------------------------------------------
    def save_report(self):
        r = self.current_result
        if r is None or r.error:
            messagebox.showwarning("Rapor Yok", "Once bir dosya analiz edin.")
            return

        default_name = os.path.splitext(r.filename)[0] + "_rapor.txt"
        save_path = filedialog.asksaveasfilename(
            title="Raporu Kaydet",
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=[("Metin dosyasi", "*.txt"), ("Tum dosyalar", "*.*")]
        )
        if not save_path:
            return

        try:
            report_text = self.build_full_report_text(r)
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(report_text)
        except Exception as e:
            messagebox.showerror("Kaydetme Hatasi", f"Rapor kaydedilemedi:\n{e}")
            return

        self.status_lbl.configure(text=f"💾 Rapor kaydedildi: {save_path}")
        messagebox.showinfo("Kaydedildi", f"Tum bulgular basariyla kaydedildi:\n{save_path}")

    def build_full_report_text(self, r):
        """
        Analiz sonucundaki TUM bulgulari (PE Info, Imports, Win API, Exports,
        Strings, Assembly, Decompile, Supheli API/Risk Skoru) tek bir duz metin
        raporu olarak birlestirir. UI'daki aktif filtrelerden bagimsizdir;
        bulunan her sey rapora dahil edilir.
        """
        L = []
        sep = "=" * 74

        L.append(sep)
        L.append(" 🦊 FOX DLL EXPLORER - ANALIZ RAPORU")
        L.append(sep)
        L.append(f"Dosya Adi     : {r.filename}")
        L.append(f"Dosya Yolu    : {r.filepath}")
        L.append(f"Rapor Tarihi  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        L.append(f"Tur           : {'.NET Assembly' if r.is_dotnet else 'Native PE (C/C++)'}")
        L.append(f"RISK SKORU    : {r.risk_score}/100  ({r.risk_level})")
        L.append("")

        if r.risk_breakdown:
            L.append("--- Risk Skoru Detayi ---")
            for label, pts in r.risk_breakdown:
                L.append(f"  +{pts:<4} {label}")
            L.append("")

        # --- PE INFO ---------------------------------------------------
        L.append(sep)
        L.append(" PE / DOSYA BILGISI")
        L.append(sep)
        for key, val in r.info.items():
            if key.startswith("_"):
                continue
            L.append(f"  {key:<18}: {val}")
        L.append("")
        if r.is_dotnet:
            L.append("  Tespit: .NET Assembly")
            for reason in r.info.get("_dotnet_reasons", []):
                L.append(f"      - {reason}")
        else:
            L.append("  Tespit: Native PE (C/C++)")
        L.append("")
        L.append("  Section Listesi:")
        L.append(f"  {'Ad':<10}{'VA':<12}{'VSize':<12}{'RawSize':<12}{'Entropy':<10}")
        for sec in r.info.get("_sections", []):
            try:
                ent_flag = "  <- yuksek entropi" if float(sec["Entropy"]) >= 7.2 else ""
            except (ValueError, KeyError):
                ent_flag = ""
            L.append(
                f"  {sec['Ad']:<10}{sec['VirtualAddress']:<12}{sec['VirtualSize']:<12}"
                f"{sec['RawSize']:<12}{sec['Entropy']:<10}{ent_flag}"
            )
        L.append("")

        # --- IMPORTS -----------------------------------------------------
        L.append(sep)
        L.append(" IMPORTS")
        L.append(sep)
        if not r.imports:
            L.append("  Import bulunamadi (statik olarak baglanmis olabilir).")
        else:
            L.append(f"  Toplam {len(r.imports)} DLL, "
                      f"{sum(len(v) for v in r.imports.values())} fonksiyon import edilmis.")
            L.append("")
            for dll, funcs in r.imports.items():
                L.append(f"  [{dll}]")
                for fn in funcs:
                    L.append(f"    - {fn}")
                L.append("")

        # --- WIN API -------------------------------------------------------
        L.append(sep)
        L.append(" WINDOWS API CAGRILARI (SISTEM KATEGORISINE GORE)")
        L.append(sep)
        L.append(f"  Toplam: {r.winapi_total_count}   |   Supheli: {r.winapi_suspicious_count}")
        L.append("")
        if not r.winapi_groups:
            L.append("  Windows API cagrisi bulunamadi.")
        else:
            for sys_category in sorted(r.winapi_groups.keys()):
                entries = r.winapi_groups[sys_category]
                sus_count = sum(1 for e in entries if e[2])
                L.append(f"  > {sys_category}  ({len(entries)} cagri)"
                          f"{f'  [{sus_count} supheli]' if sus_count else ''}")
                seen = set()
                for dll, fname, is_sus, sus_cat in sorted(entries, key=lambda x: (x[0], x[1])):
                    key = (dll, fname)
                    if key in seen:
                        continue
                    seen.add(key)
                    if is_sus:
                        L.append(f"      [SUPHELI] {dll:<16} {fname:<32} ({sus_cat})")
                    else:
                        L.append(f"      [ok]      {dll:<16} {fname}")
                L.append("")

        # --- EXPORTS -------------------------------------------------------
        L.append(sep)
        L.append(" EXPORTS")
        L.append(sep)
        if not r.exports:
            L.append("  Export bulunamadi.")
        else:
            L.append(f"  Toplam {len(r.exports)} export bulundu:")
            for e in r.exports:
                L.append(f"    - {e}")
        L.append("")

        # --- STRINGS (tum kategoriler, filtreden bagimsiz) -----------------
        L.append(sep)
        L.append(" STRINGS")
        L.append(sep)
        L.append(f"  --- ASCII Stringler ({len(r.ascii_strings)}) ---")
        L.extend(f"    {s}" for s in r.ascii_strings)
        L.append("")
        L.append(f"  --- Unicode Stringler ({len(r.unicode_strings)}) ---")
        L.extend(f"    {s}" for s in r.unicode_strings)
        L.append("")
        L.append(f"  --- URL ({len(r.filtered['url'])}) ---")
        L.extend(f"    {s}" for s in r.filtered["url"])
        L.append("")
        L.append(f"  --- IP Adresleri ({len(r.filtered['ip'])}) ---")
        L.extend(f"    {s}" for s in r.filtered["ip"])
        L.append("")
        L.append(f"  --- Registry Yollari ({len(r.filtered['registry'])}) ---")
        L.extend(f"    {s}" for s in r.filtered["registry"])
        L.append("")
        L.append(f"  --- Dosya Yollari ({len(r.filtered['filepath'])}) ---")
        L.extend(f"    {s}" for s in r.filtered["filepath"])
        L.append("")
        L.append(f"  --- Supheli Komut Satirlari ({len(r.filtered['cmdline'])}) ---")
        L.extend(f"    {s}" for s in r.filtered["cmdline"])
        L.append("")

        # --- ASSEMBLY --------------------------------------------------
        L.append(sep)
        L.append(" ASSEMBLY (DISASSEMBLY)")
        L.append(sep)
        L.append("\n".join(r.disasm_lines) if r.disasm_lines else "  (Disassembly verisi yok)")
        L.append("")

        # --- DECOMPILE ---------------------------------------------------
        L.append(sep)
        L.append(" DECOMPILE / .NET TYPES")
        L.append(sep)
        if r.is_dotnet:
            if r.dotnet_types:
                L.append("  Namespace / Class / Method Listesi:")
                seen = set()
                for item in r.dotnet_types:
                    if item not in seen:
                        seen.add(item)
                        L.append(f"    {item}")
                L.append("")
            L.append("  Decompile Edilmis Kaynak Kod:")
            L.append(r.decompiled_code or "  (Kod alinamadi)")
        else:
            L.append("  Bu dosya Native PE (C/C++) olarak tespit edildi, decompile yapilmadi.")
        L.append("")

        # --- SUPHELI API / RISK -----------------------------------------
        L.append(sep)
        L.append(" SUPHELI API CAGRILARI VE RISK SKORU")
        L.append(sep)
        if not r.suspicious_hits:
            L.append("  Supheli API cagrisi tespit edilmedi.")
            L.append(f"  Risk Skoru: {r.risk_score}/100  ({r.risk_level})")
        else:
            L.append(f"  SUPHELI API CAGRILARI TESPIT EDILDI!  Risk: {r.risk_level} ({r.risk_score}/100)")
            for category, hits in r.suspicious_hits.items():
                L.append(f"\n  > [{category}]")
                seen = set()
                for dll, api in hits:
                    key = (dll, api)
                    if key in seen:
                        continue
                    seen.add(key)
                    L.append(f"      - {dll}: {api}")
            L.append("")
            L.append("  Not: Bu bulgular sadece bilgilendirme amaclidir.")
            L.append("  Bu API'ler mesru yazilimlarda da kullanilabilir.")
            L.append("  Kesin karar icin davranissal analiz gereklidir.")
        L.append("")
        L.append(sep)
        L.append(" RAPOR SONU")
        L.append(sep)

        return "\n".join(L)

    # ------------------------------------------------------------------
    # RENDER YARDIMCILARI
    # ------------------------------------------------------------------
    def _write(self, box, text):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.configure(state="disabled")

    def render_info_tab(self):
        r = self.current_result
        lines = []
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│  PE / DOSYA BILGISI".ljust(69) + "│")
        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        for key, val in r.info.items():
            if key.startswith("_"):
                continue
            lines.append(f"  {key:<18}: {val}")

        lines.append("")
        if r.is_dotnet:
            lines.append("  🟦 Tespit: .NET Assembly")
            for reason in r.info.get("_dotnet_reasons", []):
                lines.append(f"      - {reason}")
        else:
            lines.append("  🟩 Tespit: Native PE (C/C++)")

        lines.append("")
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│  SECTION LISTESI".ljust(69) + "│")
        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        lines.append(f"  {'Ad':<10}{'VA':<12}{'VSize':<12}{'RawSize':<12}{'Entropy':<10}")
        lines.append("  " + "-" * 56)
        for sec in r.info.get("_sections", []):
            entropy_val = float(sec["Entropy"])
            flag = "  ⚠ yuksek entropi" if entropy_val >= 7.2 else ""
            lines.append(
                f"  {sec['Ad']:<10}{sec['VirtualAddress']:<12}{sec['VirtualSize']:<12}"
                f"{sec['RawSize']:<12}{sec['Entropy']:<10}{flag}"
            )

        self._write(self.info_box, "\n".join(lines))

    def render_imports_tab(self):
        r = self.current_result
        lines = []
        if not r.imports:
            lines.append("  Import bulunamadi (statik olarak baglanmis olabilir).")
        else:
            lines.append(f"  Toplam {len(r.imports)} DLL, "
                          f"{sum(len(v) for v in r.imports.values())} fonksiyon import edilmis.\n")
            for dll, funcs in r.imports.items():
                lines.append(f"📦 {dll}")
                for f in funcs:
                    lines.append(f"    - {f}")
                lines.append("")
        self._write(self.imports_box, "\n".join(lines))

    def render_winapi_tab(self):
        """
        🛡 Win API sekmesini doldurur: sistem kategorisine gore gruplanmis
        Windows API cagrilari, supheli olanlar isaretlenerek.
        """
        r = self.current_result
        if r is None:
            return

        only_suspicious = (self.winapi_filter_var.get() == "Sadece Supheli Olanlar")

        self.winapi_summary_lbl.configure(
            text=f"Toplam: {r.winapi_total_count}   |   🚨 Supheli: {r.winapi_suspicious_count}"
        )

        lines = []
        if not r.winapi_groups:
            lines.append("  Windows API cagrisi bulunamadi.")
            self._write(self.winapi_box, "\n".join(lines))
            return

        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│  🛡 WINDOWS API CAGRILARI (SISTEM KATEGORISINE GORE)".ljust(69) + "│")
        lines.append("└" + "─" * 68 + "┘")
        lines.append("")

        # Kategorileri onem sirasina gore degil, alfabetik/gruplu goster
        for sys_category in sorted(r.winapi_groups.keys()):
            entries = r.winapi_groups[sys_category]
            if only_suspicious:
                entries = [e for e in entries if e[2]]  # sadece supheli_mi=True
                if not entries:
                    continue

            sus_count = sum(1 for e in entries if e[2])
            header_flag = f"  🚨 {sus_count} supheli" if sus_count else ""
            lines.append(f"▶ {sys_category}  ({len(entries)} cagri){header_flag}")
            lines.append("  " + "-" * 60)

            # Ayni DLL:fonksiyon tekrarlarini birlestir
            seen = set()
            for dll, fname, is_sus, sus_cat in sorted(entries, key=lambda x: (x[0], x[1])):
                key = (dll, fname)
                if key in seen:
                    continue
                seen.add(key)
                if is_sus:
                    lines.append(f"    🚨 {dll:<16} {fname:<32} [{sus_cat}]")
                else:
                    lines.append(f"    ✓  {dll:<16} {fname}")
            lines.append("")

        if only_suspicious and not any("🚨" in ln for ln in lines):
            lines.append("  ✅ Supheli olarak isaretlenen Win API cagrisi bulunamadi.")

        self._write(self.winapi_box, "\n".join(lines))

    def render_exports_tab(self):
        r = self.current_result
        lines = []
        if not r.exports:
            lines.append("  Export bulunamadi (bu DLL herhangi bir fonksiyon export etmiyor olabilir).")
        else:
            lines.append(f"  Toplam {len(r.exports)} export bulundu:\n")
            for e in r.exports:
                lines.append(f"  ➜ {e}")
        self._write(self.exports_box, "\n".join(lines))

    def render_strings_tab(self):
        r = self.current_result
        if r is None:
            return
        filt = self.string_filter_var.get()
        lines = []

        if filt == "Tumu":
            lines.append(f"--- ASCII Stringler ({len(r.ascii_strings)}) ---")
            lines.extend(r.ascii_strings[:2000])
            lines.append("")
            lines.append(f"--- Unicode Stringler ({len(r.unicode_strings)}) ---")
            lines.extend(r.unicode_strings[:2000])
        elif filt == "ASCII":
            lines.append(f"Toplam {len(r.ascii_strings)} ASCII string:\n")
            lines.extend(r.ascii_strings)
        elif filt == "Unicode":
            lines.append(f"Toplam {len(r.unicode_strings)} Unicode string:\n")
            lines.extend(r.unicode_strings)
        elif filt == "URL":
            lines.append(f"Toplam {len(r.filtered['url'])} URL bulundu:\n")
            lines.extend(r.filtered["url"])
        elif filt == "IP Adresleri":
            lines.append(f"Toplam {len(r.filtered['ip'])} IP adresi bulundu:\n")
            lines.extend(r.filtered["ip"])
        elif filt == "Registry":
            lines.append(f"Toplam {len(r.filtered['registry'])} registry yolu bulundu:\n")
            lines.extend(r.filtered["registry"])
        elif filt == "Dosya Yollari":
            lines.append(f"Toplam {len(r.filtered['filepath'])} dosya yolu bulundu:\n")
            lines.extend(r.filtered["filepath"])
        elif filt == "Komut Satirlari":
            lines.append(f"Toplam {len(r.filtered['cmdline'])} supheli komut satiri ifadesi bulundu:\n")
            lines.extend(r.filtered["cmdline"])

        if not lines:
            lines = ["(Sonuc bulunamadi)"]

        self._write(self.strings_box, "\n".join(lines))

    def render_asm_tab(self):
        r = self.current_result
        text = "\n".join(r.disasm_lines) if r.disasm_lines else "(Disassembly verisi yok)"
        self._write(self.asm_box, text)

    def render_decompile_tab(self):
        r = self.current_result
        lines = []
        if r.is_dotnet:
            if r.dotnet_types:
                lines.append("┌" + "─" * 68 + "┐")
                lines.append("│  NAMESPACE / CLASS / METHOD LISTESI".ljust(69) + "│")
                lines.append("└" + "─" * 68 + "┘")
                seen = set()
                for item in r.dotnet_types:
                    if item not in seen:
                        seen.add(item)
                        lines.append("  " + item)
                lines.append("")
            lines.append("┌" + "─" * 68 + "┐")
            lines.append("│  DECOMPILE EDILMIS KAYNAK KOD".ljust(69) + "│")
            lines.append("└" + "─" * 68 + "┘")
            lines.append("")
            lines.append(r.decompiled_code or "(Kod alinamadi)")
        else:
            lines.append("  Bu dosya Native PE (C/C++) olarak tespit edildi.")
            lines.append("  .NET decompile islemi yalnizca .NET Assembly dosyalari icin yapilir.")
            lines.append("  Native kod icin '⚙ Assembly' sekmesindeki disassembly'e bakiniz.")

        self._write(self.decompile_box, "\n".join(lines))

    def render_suspicious_tab(self):
        r = self.current_result
        lines = []
        if not r.suspicious_hits:
            lines.append("  ✅ Supheli API cagrisi tespit edilmedi.")
            lines.append("")
            lines.append(f"  Risk Skoru: {r.risk_score}/100  ({r.risk_level})")
        else:
            lines.append(f"  🚨 SUPHELI API CAGRILARI TESPIT EDILDI!   "
                          f"Risk: {r.risk_level} ({r.risk_score}/100)")
            lines.append("  " + "=" * 66)
            for category, hits in r.suspicious_hits.items():
                lines.append(f"\n  ▶ [{category}]")
                seen = set()
                for dll, api in hits:
                    key = (dll, api)
                    if key in seen:
                        continue
                    seen.add(key)
                    lines.append(f"      - {dll}: {api}")
            lines.append("")
            lines.append("  " + "-" * 66)
            lines.append("  Not: Bu bulgular sadece bilgilendirme amaclidir.")
            lines.append("  Bu API'ler mesru yazilimlarda da kullanilabilir.")
            lines.append("  Kesin karar icin davranissal analiz gereklidir.")

        self._write(self.suspicious_box, "\n".join(lines))


# ===========================================================================
# GIRIS NOKTASI
# ===========================================================================

def main():
    try:
        app = FoxDLLExplorer()
        app.mainloop()
    except Exception as e:
        print(f"Uygulama baslatilamadi: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()

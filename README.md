# 🦊 FOX DLL Explorer

**TR:** Windows DLL/EXE dosyalarını analiz etmek için geliştirilmiş, Python tabanlı masaüstü PE analiz aracıdır.
**EN:** A Python-based desktop PE analysis tool designed to analyze Windows DLL/EXE files.

---

## 🇹🇷 Türkçe

### 📌 Hakkında

**FOX DLL Explorer**, Windows ortamındaki `.DLL`, `.EXE`, `.OCX` ve `.SYS` gibi PE tabanlı dosyaların statik analizini gerçekleştirmek için geliştirilmiştir.

Program; dosyanın **PE bilgilerini, Imports/Exports tablolarını, Windows API çağrılarını, string değerlerini ve Assembly kodunu** inceleyebilir. `.NET Assembly` dosyaları için sistemde `ilspycmd` mevcutsa C# kaynak kodu decompile edilebilir.

> ⚠️ **Önemli:** Risk skoru bir antivirüs veya kesin malware tespit motoru değildir. Sonuçlar statik analiz ve sezgisel göstergelere dayanır.

---

### ✨ Özellikler

* 🔍 **.NET / Native PE Detection**
* 📦 PE / Dosya bilgileri
* 📥 Imports analizi
* 🛡️ Windows API analizi
* 📤 Exports analizi
* 📝 ASCII / Unicode Strings analizi
* 🌐 URL ve IP tespiti
* 📁 Dosya yolu ve Registry string tespiti
* 💻 Komut satırı ifadelerinin tespiti
* ⚙️ x86 / x64 Assembly disassembly
* 🧩 `.NET` dosyaları için C# decompile
* 🚨 Şüpheli API tespiti
* 📊 0–100 arası sezgisel risk skoru
* 🟢 Düşük / 🟡 Orta / 🟠 Yüksek / 🔴 Kritik risk seviyeleri
* 💾 Ayrıntılı `.txt` analiz raporu oluşturma
* 🌙 Dark Mode arayüz
* 🦊 CustomTkinter tabanlı modern GUI
* ⚡ Analiz işlemlerini ayrı thread üzerinde çalıştırarak GUI'nin donmasını önleme

Programın analiz sonucu `.NET` veya `Native PE` olarak sınıflandırılır ve ilgili analiz sekmeleri otomatik olarak doldurulur.

---

### 🛡️ Şüpheli API Analizi

FOX DLL Explorer aşağıdaki kategorilerde şüpheli API çağrılarını kontrol eder:

| Kategori              | Örnekler                                                  |
| --------------------- | --------------------------------------------------------- |
| Process / Injection   | `OpenProcess`, `WriteProcessMemory`, `CreateRemoteThread` |
| Keyboard / Input      | `SetWindowsHookEx`, `GetAsyncKeyState`                    |
| Network               | `socket`, `connect`, `InternetOpen`                       |
| Screen / Capture      | `BitBlt`, `GetDC`, `StretchBlt`                           |
| Registry              | `RegOpenKeyEx`, `RegSetValueEx`                           |
| Anti-Debug / Evasion  | `IsDebuggerPresent`, `NtQueryInformationProcess`          |
| Persistence / Service | `CreateService`, `StartService`                           |
| Crypto / Packer       | `VirtualProtect`, `LoadLibrary`, `GetProcAddress`         |

Şüpheli API'ler analiz sırasında kategorilerine ayrılır ve risk skoruna katkıda bulunabilir.

---

### 📊 Risk Skoru

Risk sistemi **0–100** arasında sezgisel bir puan üretir.

* 🟢 **0–19:** Düşük
* 🟡 **20–44:** Orta
* 🟠 **45–69:** Yüksek
* 🔴 **70–100:** Kritik

Skor; şüpheli API'ler, yüksek section entropy değeri, URL/IP/komut satırı stringleri ve bazı PE özellikleri gibi statik analiz sinyallerine göre hesaplanır.

**Bu skor kesin bir zararlı yazılım kararı değildir.** Bir dosyanın yüksek skor alması tek başına malware olduğu anlamına gelmez.

---

### 🖥️ Arayüz

Arayüz aşağıdaki ana bölümlerden oluşur:

* 📦 PE Info
* 📥 Imports
* 🛡️ Win API
* 📤 Exports
* 📝 Strings
* ⚙️ Assembly
* 💻 Decompiled C#
* 🚨 Şüpheli API

Win API sekmesi Windows API çağrılarını sistem kategorilerine göre gruplandırır ve şüpheli olanları ayrıca işaretler.

---

### 📋 Analiz Raporu

Analiz tamamlandıktan sonra sonuçlar `.txt` olarak kaydedilebilir.

Raporda:

* Dosya adı ve yolu
* Analiz tarihi
* Dosya türü
* Risk skoru
* Risk gerekçeleri
* PE bilgileri
* Sections
* Imports
* Exports
* Strings
* Win API
* Assembly
* Decompiled C#
* Şüpheli API bulguları

gibi analiz sonuçları bir araya getirilir.

---

### ⚙️ Gereksinimler

* Windows
* Python 3.x
* `customtkinter`
* `pefile`
* `capstone`

Kurulum:

```bash
pip install customtkinter pefile capstone
```

.NET decompile özelliği için:

```bash
dotnet tool install -g ilspycmd
```

`ilspycmd` opsiyoneldir. Kurulu değilse program çalışmaya devam eder ve kullanıcıya gerekli kurulum bilgisini gösterir.

---

### ▶️ Çalıştırma

```bash
python fox_dll_explorer.py
```

Ardından **Dosya Aç** butonundan analiz etmek istediğiniz DLL/EXE dosyasını seçebilirsiniz.

---

### ⚠️ Sorumluluk Reddi

Bu yazılım yalnızca **eğitim, araştırma, yazılım geliştirme ve güvenlik analizi** amacıyla kullanılmalıdır.

FOX DLL Explorer tarafından oluşturulan risk skorları ve analiz sonuçları kesin güvenlik hükmü olarak değerlendirilmemelidir.

Bir dosyanın güvenli veya zararlı olduğuna karar vermeden önce gerektiğinde ek analiz araçları ve profesyonel malware analiz yöntemleri kullanılmalıdır.

---

## 🇬🇧 English

### 📌 About

**FOX DLL Explorer** is a Python-based desktop PE analysis tool designed to perform static analysis of Windows `.DLL`, `.EXE`, `.OCX`, and `.SYS` files.

The application can inspect **PE information, Imports, Exports, Windows API calls, strings, and Assembly instructions**. For `.NET Assembly` files, the application can optionally use `ilspycmd` to decompile the file into C# source code.

> ⚠️ **Important:** The risk score is not an antivirus engine or a definitive malware detection system. Results are based on static analysis and heuristic indicators.

---

### ✨ Features

* 🔍 **.NET / Native PE Detection**
* 📦 PE / File information
* 📥 Import analysis
* 🛡️ Windows API analysis
* 📤 Export analysis
* 📝 ASCII / Unicode string analysis
* 🌐 URL and IP detection
* 📁 File path and Registry string detection
* 💻 Command-line indicator detection
* ⚙️ x86 / x64 Assembly disassembly
* 🧩 C# decompilation for `.NET` files
* 🚨 Suspicious API detection
* 📊 Heuristic risk score from 0–100
* 🟢 Low / 🟡 Medium / 🟠 High / 🔴 Critical risk levels
* 💾 Detailed `.txt` analysis reports
* 🌙 Dark Mode interface
* 🦊 Modern CustomTkinter GUI
* ⚡ Background analysis to keep the GUI responsive

The analysis engine identifies files as either `.NET Assembly` or `Native PE` and processes them accordingly.

---

### 🛡️ Suspicious API Detection

FOX DLL Explorer checks suspicious APIs in several categories:

| Category              | Examples                                                  |
| --------------------- | --------------------------------------------------------- |
| Process / Injection   | `OpenProcess`, `WriteProcessMemory`, `CreateRemoteThread` |
| Keyboard / Input      | `SetWindowsHookEx`, `GetAsyncKeyState`                    |
| Network               | `socket`, `connect`, `InternetOpen`                       |
| Screen / Capture      | `BitBlt`, `GetDC`, `StretchBlt`                           |
| Registry              | `RegOpenKeyEx`, `RegSetValueEx`                           |
| Anti-Debug / Evasion  | `IsDebuggerPresent`, `NtQueryInformationProcess`          |
| Persistence / Service | `CreateService`, `StartService`                           |
| Crypto / Packer       | `VirtualProtect`, `LoadLibrary`, `GetProcAddress`         |

Suspicious APIs are categorized during analysis and can contribute to the heuristic risk score.

---

### 📊 Risk Score

The heuristic engine generates a score between **0 and 100**:

* 🟢 **0–19:** Low
* 🟡 **20–44:** Medium
* 🟠 **45–69:** High
* 🔴 **70–100:** Critical

The score may consider suspicious APIs, high section entropy, URL/IP/command-line strings, and other static PE indicators.

**The score is not a definitive malware verdict.** A high score alone does not prove that a file is malicious.

---

### 🖥️ Interface

The application provides the following analysis tabs:

* 📦 PE Info
* 📥 Imports
* 🛡️ Win API
* 📤 Exports
* 📝 Strings
* ⚙️ Assembly
* 💻 Decompiled C#
* 🚨 Suspicious API

The Win API tab groups Windows API calls by system category and highlights suspicious calls.

---

### 📋 Analysis Reports

After an analysis is completed, the complete result can be exported as a `.txt` report.

The report may contain:

* File name and path
* Analysis date
* File type
* Risk score
* Risk breakdown
* PE information
* Sections
* Imports
* Exports
* Strings
* Win API
* Assembly
* Decompiled C#
* Suspicious API findings

All detected findings are combined into a single text report.

---

### ⚙️ Requirements

* Windows
* Python 3.x
* `customtkinter`
* `pefile`
* `capstone`

Install dependencies:

```bash
pip install customtkinter pefile capstone
```

Optional `.NET` decompilation support:

```bash
dotnet tool install -g ilspycmd
```

`ilspycmd` is optional. If it is not installed, the application continues to work and displays installation instructions when .NET decompilation is requested.

---

### ▶️ Usage

```bash
python fox_dll_explorer.py
```

Then click **Open File** and select the DLL/EXE file you want to analyze.

---

### ⚠️ Disclaimer

This software is intended for **educational, research, software development, and security analysis purposes**.

Risk scores and analysis results generated by FOX DLL Explorer should not be considered definitive security verdicts.

Additional analysis tools and professional malware-analysis techniques should be used when determining whether a file is safe or malicious.

---

## 📄 License

See the repository's `LICENSE` file for licensing information.

---

## 🦊 FOXTR

**FOX DLL Explorer — PE / .NET Static Analysis Tool**

Made for developers, researchers and security enthusiasts.

**🇹🇷 Türkçe • 🇬🇧 English**

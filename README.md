# Cactus Hack Detector

**Cactus Hack Detector** is a free Windows Minecraft hack detector and security scanner designed to identify suspicious Minecraft mods, hacked clients, cheat modules, and potential malware indicators.

Whether you're investigating a suspicious Minecraft mod, checking for hacked clients, or auditing a Minecraft installation, MC Scan helps identify suspicious files and system activity and generates a detailed JSON scan report.

## Features

- **Minecraft Mod Scanner:** Analyze Minecraft mods for suspicious code and known cheat indicators.
- **Hacked Client Detection:** Look for traces associated with known hacked Minecraft clients.
- **Cheat Module Detection:** Identify indicators associated with KillAura, Fly, and other cheat modules.
- **Keybind Detection:** Identify suspicious cheat-related keybinds where available.
- **Malware Indicators:** Search for potentially malicious Minecraft-related files and activity.
- **Detailed Scan Reports:** Generate JSON reports containing scan results and evidence.

## Supported Platform

- Windows 10
- Windows 11
- PowerShell 5.1 or newer

## Quick Start

Download `Scan.ps1` from this repository and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Scan.ps1
irm https://raw.githubusercontent.com/Vemmba/CactusHacksDetector/main/Scan.ps1 | iex
```

Administrator privileges are recommended for additional scanning capabilities.

## Project

- Source code: https://github.com/Vemmba/CactusHacksDetector
- Issues and bug reports: https://github.com/Vemmba/CactusHacksDetector/issues

**Disclaimer:** MC Scan is an investigative security tool. Suspicious indicators are not definitive proof of cheating or malware, and false positives are possible.

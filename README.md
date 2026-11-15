# CactusHacksDetector

**A Minecraft security scanner for Windows.**

CactusHacksDetector checks your Minecraft installation for suspicious mods, hacked clients, cheat modules, malware indicators, and unusual system activity that may be related to cheating.

It generates a detailed report so suspicious findings can be reviewed.

## Features

- **Mod scanning:** Checks Minecraft mods for known cheats, suspicious code, and malware indicators.
- **Hack detection:** Identifies suspicious modules such as KillAura, Fly, and other cheat features.
- **Keybind detection:** Finds toggle keys associated with detected modules when available.
- **Client detection:** Checks for signs of known hacked clients and suspicious Minecraft activity.
- **System activity:** Looks for relevant traces of injectors, cheat tools, and unusual activity.
- **Detailed reports:** Displays findings and saves a JSON report locally.

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or newer
- An internet connection
- Administrator privileges recommended for a more complete scan

## How to use

1. Open PowerShell (as Administrator is recommended).
2. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
irm https://raw.githubusercontent.com/Vemmba/CactusHacksDetector/main/Scan.ps1 | iex
```

3. When prompted, type your Minecraft username.
4. Wait for the scan to finish.
5. Review the results.

## What it analyzes

- **Minecraft mods:** Jar files in your mods folders, checked for known cheat signatures, suspicious code, and malware indicators.
- **Cheat modules and keybinds:** Module names such as KillAura and Fly, plus their toggle keys when available.
- **Hacked clients:** Known client files, folders, and launcher traces.
- **Launcher data:** Minecraft account information found in the launcher.
- **System activity:** Traces of injectors, cheat tools, recently run programs, and other unusual activity related to cheating.

## Scan results

| Result | Meaning |
|---|---|
| NO FINDINGS | No significant suspicious indicators were detected. |
| MINOR NOTES | Minor findings that may need attention. |
| REVIEW | Suspicious activity requires further investigation. |
| HIGH RISK | Multiple or significant suspicious indicators were detected. |
| MALWARE FOUND | Strong malware indicators were detected. |

**Important:** A detection is not automatic proof of cheating. Some legitimate mods and applications may trigger suspicious indicators. Results should be reviewed before taking action.

## Reports

Every completed scan generates a JSON report, saved in:

```text
%TEMP%\CactusHacksDetector
```

Each report contains scan information, detected mods, findings, and relevant evidence.

## Troubleshooting

**PowerShell scripts are blocked**
Run `Set-ExecutionPolicy -Scope Process Bypass -Force` in the same window, then run the scanner again.

**Some checks show skipped or errors**
Some checks require Administrator privileges or Windows logging features to be enabled.

**A legitimate mod is flagged**
False positives are possible. Review the detection details before assuming a mod is malicious.

**Minecraft is not detected**
Make sure your Minecraft launcher and installation folders are accessible.

## Disclaimer

CactusHacksDetector is a security analysis tool, not an absolute cheating detector.

A clean result does not guarantee that a computer is free from cheats or malware. A suspicious result does not automatically prove wrongdoing.

Use the findings as evidence for further investigation.

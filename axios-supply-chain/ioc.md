# IOCs — Axios npm Supply Chain Attack
**Date:** March 30, 2026  
**Threat Actor:** UNC1069 (DPRK-nexus)  
**Malware:** WAVESHAPER.V2 (Cross-platform RAT)

> ⚠️ All network IOCs are defanged. Replace `[.]` with `.` before using in tooling.

---

## Malicious Package Versions

| Package | Malicious Version | Safe Version |
|---------|-------------------|--------------|
| `axios` | `1.14.1` | `1.14.0` or earlier |
| `axios` | `0.30.4` | `0.30.3` or earlier |
| `plain-crypto-js` | `4.2.0` | N/A — avoid entirely |
| `plain-crypto-js` | `4.2.1` | N/A — avoid entirely |

---

## Network IOCs

| Type | Value | Notes |
|------|-------|-------|
| C2 Domain | `sfrclak[.]com` | Primary C2 — block egress |
| C2 IP | `142.11.206[.]73` | Block at firewall/EDR |
| C2 Port | `8000` | Outbound HTTP POST |
| Attacker Email | `ifstap@proton[.]me` | Used to hijack npm account |

---

## File System IOCs

### Windows
| Artifact | Path |
|----------|------|
| Persistence batch file | `%PROGRAMDATA%\system.bat` |
| Registry run key | `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate` |
| Temp dropper | `%TEMP%\6202033*` |

### macOS / Linux
| Artifact | Path |
|----------|------|
| Temp dropper | `/tmp/6202033*` |

---

## File Hashes (SHA-256)

```
ad8ba560ae5c4af4758bc68cc6dcf43bae0e0bbf9da680a8dc60a9ef78e22ff7
fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf
cdc05cd30eb53315dadb081a7b942bb876f0d252d20e8ed4d2f36be79ee691fa
8449341ddc3f7fcc2547639e21e704400ca6a8a6841ae74e57c04445b1276a10
01c9484abc948daa525516464785009d1e7a63ffd6012b9e85b56477acc3e624
7b47ed28e84437aee64ffe9770d315c1b984135105f7f608a8b9579517bc0695
```

---

## User-Agent String (WAVESHAPER.V2 Beacon)

```
mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)
```
> Alert on this UA string in proxy/web gateway logs, especially from Node.js processes.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Supply Chain Compromise | T1195.002 |
| Initial Access | Phishing / Social Engineering | T1566 |
| Execution | Command and Scripting Interpreter | T1059 |
| Execution | User Execution (malicious package install) | T1204.002 |
| Persistence | Registry Run Keys (Windows) | T1547.001 |
| Defense Evasion | Indicator Removal — File Deletion | T1070.004 |
| Discovery | System Information Discovery | T1082 |
| Discovery | Process Discovery | T1057 |
| Command & Control | Application Layer Protocol (HTTP) | T1071.001 |
| Command & Control | Ingress Tool Transfer | T1105 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

---

## Quick Check Commands

```bash
# Check if malicious axios version is installed
npm list axios

# Search lockfiles for phantom dependency
grep -r "plain-crypto-js" package-lock.json yarn.lock pnpm-lock.yaml

# Search npm cache for malicious package
find ~/.npm -name "plain-crypto-js" 2>/dev/null

# Check for persistence artifact (Windows PowerShell)
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object MicrosoftUpdate

# Check for persistence batch file (Windows)
Test-Path "$env:PROGRAMDATA\system.bat"
```

---

## Remediation Checklist

- [ ] Downgrade axios to `1.14.0` / `0.30.3` or pin in lockfile
- [ ] Remove `plain-crypto-js` from all dependency trees
- [ ] Clear npm/yarn/pnpm cache on all dev machines and build servers
- [ ] Block `sfrclak[.]com` and `142.11.206[.]73` at firewall
- [ ] Rotate all credentials, API keys, SSH keys on exposed machines
- [ ] Check for `%PROGRAMDATA%\system.bat` and registry run key (Windows)
- [ ] Check `/tmp/6202033*` artifacts (macOS/Linux)
- [ ] Pause CI/CD pipelines using axios until validated
- [ ] Hunt network logs for C2 domain/IP during exposure window

---

*Report authored by: mindsecset | virtueofvague.com*  
*Last updated: April 2026*

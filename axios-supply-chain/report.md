# Threat Report: Axios npm Supply Chain Attack

| Field | Details |
|-------|---------|
| **Date** | March 30, 2026 |
| **Severity** | Critical |
| **Type** | Supply Chain Attack / Software Dependency Poisoning |
| **Threat Actor** | UNC1069 (North Korea-nexus / DPRK-attributed) |
| **Malware** | WAVESHAPER.V2 (Cross-platform RAT) |
| **Status** | Contained — malicious packages removed from npm |

---

## Summary

Axios, one of the most widely used JavaScript HTTP client libraries with over **100 million weekly npm downloads**, was compromised in a sophisticated supply chain attack on March 30, 2026. The attacker hijacked the npm account of the lead maintainer (`jasonsaayman`), published two backdoored versions of the package, and used a phantom dependency to deploy a cross-platform Remote Access Trojan (RAT) on victim machines running macOS, Windows, and Linux. The malware self-destructed after execution to evade detection.

The attack has been attributed to **UNC1069**, a North Korea-nexus threat actor, and is considered one of the largest supply chain compromises in npm history.

---

## Timeline

| Time (UTC) | Event |
|------------|-------|
| ~18 hrs before publish | Malicious dependency `plain-crypto-js@4.2.0/4.2.1` seeded on npm registry |
| March 30, 2026 | Attacker compromises `jasonsaayman` npm account via social engineering |
| March 30 | Account email changed to `ifstap@proton[.]me` |
| March 30 | `axios@1.14.1` published manually via stolen npm token |
| ~39 min later | `axios@0.30.4` published — both branches (1.x and legacy 0.x) now poisoned |
| Same day | Attacker uses hijacked credentials to delete GitHub disclosure issues |
| March 30 (night) | Elastic Security researcher detects compromise via AI-powered diff monitoring |
| March 30 (night) | Huntress SOC confirms 135+ hosts contacting C2 across customer environments |
| Shortly after | Axios team pulls malicious packages from npm |
| Shortly after | C2 infrastructure goes offline due to overload |

---

## Attack Chain (TTPs)

### Phase 1 — Initial Access: Social Engineering
The attacker did not use a simple credential leak. Instead, they ran a **targeted social engineering operation**:

- Impersonated a legitimate company
- Constructed a convincing **fake Slack workspace** with cloned branding and profiles of known engineers
- Arranged a live **Microsoft Teams meeting** with the maintainer
- During the meeting, tricked the maintainer into installing what appeared to be a routine software update — which was in reality the initial-access malware used to compromise their environment

### Phase 2 — Pre-Staging the Payload
Before compromising the maintainer account, the attacker pre-seeded the malicious phantom dependency (`plain-crypto-js@4.2.1`) on the npm registry. This was done to:
- Avoid "brand-new package" detection alarms
- Ensure the payload was ready the moment the poisoned Axios versions were published

### Phase 3 — Account Takeover & Bypassing OIDC
- The maintainer's npm account email was changed to an attacker-controlled ProtonMail address
- Every legitimate Axios 1.x release is published via **GitHub Actions with npm's OIDC Trusted Publisher** mechanism — binding publishes to a verified CI workflow
- However, the workflow also passed `NPM_TOKEN` as an environment variable alongside OIDC credentials. **When both are present, npm uses the token** — making the long-lived token the effective authentication method regardless of OIDC configuration
- The attacker published both malicious versions **manually via npm CLI**, leaving no GitHub commit, tag, or release trail

### Phase 4 — Malicious Dependency Injection
- The poisoned Axios versions imported `plain-crypto-js@4.2.1` as a **phantom dependency**
- On installation, a **postinstall hook** executed the RAT dropper
- The attack propagated **transitively** — any package that depended on axios (e.g., WordPress modules, Datadog packages) also pulled in the malicious dependency

### Phase 5 — RAT Deployment (WAVESHAPER.V2)
The malware deployed a cross-platform RAT with the following capabilities:

- **Beacon**: Base64-encoded JSON data sent to C2, using a hardcoded legacy User-Agent:  
  `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)`
- **Polling**: Continuously polls C2 server every 60 seconds awaiting commands
- **Reconnaissance**: Extracts hostname, username, OS version, boot time, timezone, running process list
- **Persistence (Windows)**: Creates hidden batch file at `%PROGRAMDATA%\system.bat` and adds registry key `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`

### Phase 6 — Anti-Forensics
After execution, the malware **replaced its own files with clean decoys** — making post-incident detection significantly harder for teams without pre-compromise telemetry.

---

## Indicators of Compromise (IOCs)

### Malicious Package Versions
| Package | Version |
|---------|---------|
| `axios` | `1.14.1` |
| `axios` | `0.30.4` |
| `plain-crypto-js` | `4.2.0` |
| `plain-crypto-js` | `4.2.1` |

### Network IOCs
| Type | Value |
|------|-------|
| C2 Domain | `sfrclak[.]com` |
| C2 IP | `142.11.206[.]73` |
| C2 Port | `8000` |
| Attacker Email | `ifstap@proton[.]me` |

### File System IOCs (Windows)
| Artifact | Path |
|----------|------|
| Persistence batch file | `%PROGRAMDATA%\system.bat` |
| Registry key | `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate` |
| Temp dropper pattern | `*\Temp\6202033*` |

### File Hashes (SHA-256)
```
ad8ba560ae5c4af4758bc68cc6dcf43bae0e0bbf9da680a8dc60a9ef78e22ff7
fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf
cdc05cd30eb53315dadb081a7b942bb876f0d252d20e8ed4d2f36be79ee691fa
8449341ddc3f7fcc2547639e21e704400ca6a8a6841ae74e57c04445b1276a10
01c9484abc948daa525516464785009d1e7a63ffd6012b9e85b56477acc3e624
7b47ed28e84437aee64ffe9770d315c1b984135105f7f608a8b9579517bc0695
```

---

## Affected Systems

- **OS**: Windows, macOS, Linux
- **Runtime**: Node.js environments with npm/yarn/pnpm
- **Sectors impacted**: Government, Financial Services, Technology (US, Europe, Middle East, South Asia, Australia)
- **Transitive exposure**: Any project or package using axios as a dependency — including internal tools, CI/CD pipelines, and third-party integrations

---

## Detection & Hunting Queries

### Check for Malicious Package in Your Environment
```bash
# Check installed axios version
npm list axios

# Check lockfile for phantom dependency
grep -r "plain-crypto-js" package-lock.json yarn.lock pnpm-lock.yaml
```

### Trend Micro Vision One
```
# Detect temp file creation by postinstall dropper
eventSubId:101 AND objectFilePath:(*\Temp\6202033* OR */tmp/6202033*) AND parentFilePath:(*\node.exe OR */node)

# Detect outbound C2 connections
eventSubId:204 AND dst:("sfrclak.com" OR "142.11.206.73")
```

### Network Detection
- Monitor for outbound HTTP POST requests to `sfrclak[.]com` or `142.11.206[.]73` on port 8000
- Alert on beaconing behavior with 60-second intervals from Node.js processes
- Look for the legacy User-Agent string: `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)`

---

## Remediation Steps

### Immediate Actions
1. **Downgrade axios** to a safe version:
   - Safe: `axios@1.14.0` or earlier
   - Safe: `axios@0.30.3` or earlier
2. **Pin the version** in `package-lock.json` to prevent accidental upgrades
3. **Audit lockfiles** for `plain-crypto-js` versions `4.2.0` or `4.2.1`
4. **Block C2 traffic**: Add firewall rules for `sfrclak[.]com` and `142.11.206[.]73`
5. **Clear npm/yarn/pnpm caches** on all workstations and build servers

### If Compromise is Confirmed
- Treat the **entire host as fully compromised**
- **Rotate all credentials** — API keys, SSH keys, cloud credentials, crypto wallets, secrets stored on the machine
- Revert affected environments to a known-good state
- **Pause CI/CD pipelines** that depend on axios until validated

### Long-Term Hardening
- Use `--ignore-scripts` flag during CI/CD npm installs to block postinstall hooks
- Add `overrides` block in `package.json` to prevent transitive malicious version resolution
- Deploy EDR on developer workstations — monitor for suspicious processes spawning from Node.js
- Migrate secrets away from plaintext on developer machines into vaults (e.g., `aws-vault`, OS keychains)
- Audit npm tokens: revoke long-lived tokens and enforce OIDC-only publishing where possible
- Implement automated monitoring of package diffs on critical dependencies

---

## Broader Context

This attack did not occur in isolation. Around the same timeframe:

- **TeamPCP (UNC6780)** poisoned GitHub Actions and PyPI packages associated with **Trivy**, **Checkmarx**, and **LiteLLM**, deploying the **SANDCLOCK credential stealer**
- Credentials stolen from the Trivy breach were used to compromise LiteLLM — demonstrating how one supply chain attack enables the next
- Hundreds of thousands of stolen secrets are estimated to be circulating as a result of these cascading incidents

---

## Analyst Notes

> *Personal commentary — mindsecset perspective*

What makes this attack particularly dangerous is not just the scale (300M weekly downloads) — it's the **trust model abuse**. Developers and CI/CD pipelines implicitly trust packages they've used for years. The attacker weaponized that trust through a combination of:

1. **Human-layer compromise** (social engineering the maintainer) rather than technical exploitation
2. **Infrastructure pre-staging** (seeding the phantom dependency 18 hours early to avoid alarms)
3. **Anti-forensics by design** (the malware erasing itself after execution)

The OIDC bypass is worth highlighting for defenders: having OIDC Trusted Publishing configured is not sufficient if long-lived tokens still exist and are passed as environment variables. The security control was partially nullified by a legacy configuration detail.

For SOC teams: if you don't have pre-compromise telemetry (network logs, process logs) from the exposure window (March 30, 2026), assume you cannot fully determine scope. Rotate credentials regardless.

The detection by the Elastic researcher — using an AI-powered diff monitoring tool built in a single afternoon — is a reminder that creative, lightweight tooling can outpace enterprise solutions when it comes to supply chain visibility.

---

## References

| Source | URL |
|--------|-----|
| Trend Micro | https://www.trendmicro.com/en_us/research/26/c/axios-npm-package-compromised.html |
| Google Cloud / GTIG | https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package |
| Huntress | https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package |
| Elastic Security Labs | https://www.elastic.co/security-labs/how-we-caught-the-axios-supply-chain-attack |
| Palo Alto Unit 42 | https://unit42.paloaltonetworks.com/axios-supply-chain-attack/ |
| Vectra AI | https://www.vectra.ai/blog/breaking-down-the-axios-supply-chain-incident |
| OX Security | https://www.ox.security/blog/axios-compromised-with-a-malicious-dependency/ |

---

*Report authored by: mindsecset | virtueofvague.com*  
*Last updated: April 2026*

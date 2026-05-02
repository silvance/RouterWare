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

Four extensions in the cert each carry a beacon URL pointing at your
listener, with a unique token and channel tag baked into the query
string:

- **AIA `OCSP`** — followed by anything that performs revocation checks
- **AIA `caIssuers`** — followed by clients trying to build the chain
- **CRL distribution point** — followed by CRL-based revocation checks
- **SAN URI** — followed by some certificate parsers and crawlers

Whichever path the attacker, scanner, or curious finder takes, your
listener sees the `t=<token>&c=<channel>` parameters and you know which
deployed credential and which validation behavior tripped.

## Quickstart

```sh
pip install -r requirements.txt

# 1. Stand up the listener (use a real TLS endpoint in practice)
python canary_listener.py --port 8080 &

# 2. Mint a credential pointing at it
python generate_cac_canary.py \
  --beacon-url https://canary.lab.example/cb \
  --last DOE --first JOHN --middle Q \
  --p12-password 'changeme1!' \
  --out-dir ./canary-out

# 3. Plant the .pfx (and/or .pem) where you want monitored:
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

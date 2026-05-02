# CAC-style canary token

A toolkit for generating a deception artifact shaped like a U.S. DoD
Common Access Card backup folder — as if a careless user exported their
CAC keys with ActivClient and dropped the result on a fileshare. The
folder is designed to fingerprint the operator who finds it the moment
they browse it, well before they get to offline cryptographic analysis.

For blue-team training, honeyfile programs, and authorized internal
deception engagements (red-team, purple-team).

## What it produces

`generate_cac_canary.py` writes a `CAC Backup/` folder containing:

| File                          | Purpose                                          |
| ----------------------------- | ------------------------------------------------ |
| `<last>_<edipi>_id.pfx`       | PIV/Identity cert + key (clientAuth + smartcardLogon) |
| `<last>_<edipi>_sig.pfx`      | Digital Signature cert + key (S/MIME signing)    |
| `<last>_<edipi>_enc.pfx`      | Encryption cert + key (S/MIME key management)    |
| `<last>_<edipi>_*.cer`        | Public certs in PEM                              |
| `DoD_CA_Bundle.pem`           | Synthetic intermediate + root with DoD-shape DNs |
| `pin.txt`                     | The 6-digit PIN, in plaintext (sticky-note style)|
| `Important - CAC Reset Instructions.url` | Honeyfolder fire-on-browse beacon     |
| `How to import this CAC.html` | Honeyfolder JS fingerprint beacon                |

The manifest (`.<folder>.token.txt`) is written **outside** the planted
folder so the operator never sees it.

The certificates carry CAC-shaped metadata:

- `CN=LAST.FIRST.MIDDLE.<10-digit-EDIPI>` Subject DN, `OU=DoD/PKI/CONTRACTOR`
- Issuer `DOD ID CA-59` (matching real DoD intermediate naming)
- Per-cert EKU: ID has `clientAuth + smartcardLogon`; Sig has
  `emailProtection`; Enc has `emailProtection` with `keyEncipherment`
- ID cert SAN includes a Microsoft UPN otherName; Sig/Enc carry just
  `<edipi>@mail.mil`
- DoD `CertificatePolicies` OID `2.16.840.1.101.2.1.11.39`
- Validity dates clustered around a random "issue date" 3–9 months ago

The leaves are **self-signed**, not signed by the bundled CA. The
artifact will not authenticate to any real DoD service — that is the
safety guarantee. The bundled CA chain is for *visual* completeness in
Certificate Manager, not cryptographic validation.

## How the trip fires

Two layers, both attributed to the same per-credential `<token>` and
tagged with a `<channel>` so you can tell *what* fired. Beacon URLs
have shape:

```
https://<host>/v/<token>/[<role>/]<filename>
```

`<role>` is `id`, `sig`, or `enc` for cert-driven beacons (Layer 1) and
absent for honeyfolder beacons (Layer 2).

### Layer 1 — cert-driven (passive)

Each cert carries beacon URIs in its AIA, CRL, and SAN extensions. They
fire when something tries to *validate or use* the credential, and the
listener attributes the hit to the specific cert (id/sig/enc):

| Filename                    | Channel | Trigger                                |
| --------------------------- | ------- | -------------------------------------- |
| `ocsp`                      | `ocsp`  | OCSP revocation check                  |
| `DODIDCA-59_IT.p7c`         | `aia`   | AIA caIssuers chain-build fetch        |
| `DODIDCA59.crl`             | `crl`   | CRL-based revocation check             |
| `info`                      | `san`   | URI-SAN follow                         |

Importing the `.pfx` into a cert store typically isn't enough on its
own — these wait for the *first use* of the cert. To fingerprint the
*finder* the moment the bundle is opened, see Layer 2.

### Layer 2 — honeyfolder (fire-on-browse, OS+browser fingerprint)

Two companion files fire as soon as someone browses the planted folder
(unless `--no-companions`):

- **`Important - CAC Reset Instructions.url`** — Windows Internet
  Shortcut. `IconFile=` points at `/v/<token>/icon.ico`; **Explorer
  fetches the icon as soon as the folder is listed**, with no clicks
  (channel `icon`). `URL=` fires on double-click (channel `urlclick`).
- **`How to import this CAC.html`** — opens in the user's browser. A
  hidden 1×1 pixel beacons `/v/<token>/p.gif` (channel `img`) and an
  iframe loads `/v/<token>/page` (channel `page`). The page runs JS
  that collects:
    - User-Agent, platform, languages
    - IANA timezone
    - Screen geometry + device pixel ratio
    - `navigator.hardwareConcurrency` / `deviceMemory`
    - Plugin list
    - Canvas + WebGL renderer fingerprint
  …and POSTs the result to `/v/<token>/fp`, logged as a
  `kind=fingerprint` event.

Every request also logs source IP and full request headers
(`Accept-Language` is gold for locale, `User-Agent` for OS+browser),
so even hits that never reach the JS layer carry useful signal.

## Quickstart

```sh
pip install -r requirements.txt

# 1. Stand up the listener (use a real TLS endpoint in practice)
python canary_listener.py --port 8080 &

# 2. Mint the bundle (creates ./CAC Backup/ ready to plant)
python generate_cac_canary.py \
  --beacon-url https://pki-status.lab.example \
  --last DOE --first JOHN --middle Q

# 3. Plant the folder where you want monitored:
#    - a "Personal" share alongside other engineer/admin docs
#    - a developer's home directory (Documents/CAC Backup/)
#    - an internal wiki page that links to the zip
```

## Sending hits to S3

```sh
pip install boto3
AWS_PROFILE=canary python canary_listener.py \
  --port 8080 --s3-bucket my-canary-archive --s3-prefix demo
```

Each event is appended to stdout *and* written as a JSON object to:

```
s3://my-canary-archive/demo/events/<token>/<YYYY>/<MM>/<DD>/<ts>-<rand>.json
```

Token-major layout: a single `list_objects` under
`<prefix>/events/<token>/` enumerates every hit for that token.

Credentials come from the standard AWS chain (env vars,
`~/.aws/credentials`, instance/task role). Bucket policy needs
`s3:PutObject` on `<prefix>/events/*`.

### Alternative: skip the listener entirely

You can also point the cert beacons directly at an S3 website endpoint
and enable [S3 server access logging] on the bucket. Every
cert-validation hit then shows up in the access log bucket with source
IP, UA, and the full request URI (which carries the token + channel).

| | Listener → S3 | Direct → S3 access log |
|---|---|---|
| Real-time | yes | no — best-effort delivery, often hours |
| Captures Layer-2 JS fingerprint | yes | no (no `/page` to render) |
| Captures full headers | yes | only fields S3 logs |
| Infra to run | a host + TLS cert | none |

[S3 server access logging]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html

## Replaying a trip

```sh
# What tokens have fired at all?
python read_events.py --bucket my-canary-archive --prefix demo --list-tokens

# Full timeline for a specific token
python read_events.py --bucket my-canary-archive --prefix demo --token <T>

# Or NDJSON for downstream processing
python read_events.py --bucket my-canary-archive --prefix demo --token <T> --json | jq .
```

Sample timeline from a successful red-team trip:

```
token: 9ZWvvBvh_99_Pi5s
events: 6  channels: fingerprint=1, icon=1, id/aia=1, id/ocsp=1, img=1, sig/ocsp=1

  10:25:41  [icon          ] 10.0.5.42        Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  10:25:42  [img           ] 10.0.5.42        Mozilla/5.0 ... Edg/121.0
                                 accept-language: en-US,en;q=0.9
  10:25:42  [fingerprint   ] 10.0.5.42
      ua                 Mozilla/5.0 ... Edg/121
      platform           Win32
      timezone           America/Los_Angeles
      screen             1920x1080@24 dpr=1.25
      hw concurrency     8
      webgl              ANGLE (Intel UHD 630)
  11:42:10  [id/ocsp       ] 52.94.10.5       Microsoft-CryptoAPI/10.0
  11:42:11  [id/aia        ] 52.94.10.5       Microsoft-CryptoAPI/10.0
  13:01:00  [sig/ocsp      ] 18.205.x.x       Mozilla/5.0 (Macintosh; Intel Mac OS X 14)
```

Reads: operator browsed the folder on Windows at 10:25 (icon hit, then
HTML opened — full Windows fingerprint captured), imported the ID cert
and tried to use it ~80 minutes later (Microsoft CryptoAPI fired
OCSP+AIA from a different egress IP), and at 13:01 a different host
(maybe a teammate, maybe pivoted) probed the SIG cert from a Mac.

`read_events.py` only needs `s3:ListBucket` (scoped to the prefix) and
`s3:GetObject`. Keep the IAM principal that runs it separate from the
listener's principal — listener writes only, analyst tooling reads only.

## Training / engagement scenarios

- **Detection drills.** Plant the artifact, have the SOC explain how
  they would catch each beacon channel, then trip them and verify the
  alert path end-to-end via `read_events.py`.
- **Red-team engagement.** Plant on a fileshare during a normal pivot
  path. The honeyfolder fingerprints the operator within seconds of
  browse; per-cert OCSP attribution then tells you which key they
  imported and tried to use.
- **Validation hygiene.** Show new analysts how merely opening the
  `.pfx`, importing it into a cert store, *or* even browsing the
  folder, will phone home — driving home the rule that found
  credentials must be triaged offline.

## Operational notes

- Run the listener behind TLS with a cert your environment trusts;
  otherwise some clients won't connect and you'll miss trips.
- The default PIN is a random 6 digits, written to `pin.txt` as
  plaintext. Override with `--pin <digits>`.
- The manifest stays outside the planted folder. Keep it in your
  deception inventory so you can map a token back to a deployment.
- The artifact does **not** sign with any real CA, embed EDIPIs of real
  persons, or mimic specific living individuals. Use synthetic names.
- The generator refuses `--beacon-url` values pointing at well-known
  public OOB services (canarytokens.org, webhook.site, interact.sh,
  oast.fun, requestbin, etc.). Override with `--allow-public-callback`.

# RouterWare canary toolkit

> **Synthetic deception artifact only.** Generates self-contained
> CAC-shaped honey credentials and document beacons for blue-team
> training and authorized deception engagements. Do **not** plant
> outside environments you own or have written authorization to test
> in. Do **not** use the names or EDIPIs of real persons; the
> generator defaults to synthetic values and you should keep it that
> way. The artifact is signed by a synthetic CA chain and will not
> authenticate to real DoD systems by design. If you don't have an
> authorization document for the environment you're planting in,
> stop here.

The default workflow generates a folder shaped like a U.S. DoD Common
Access Card backup — as if a careless user exported their CAC keys
with ActivClient and dropped the result on a fileshare. The folder is
designed to fingerprint the operator who finds it the moment they
browse it, well before they get to offline cryptographic analysis.

For blue-team training, honeyfile programs, and authorized internal
deception engagements (red-team, purple-team).

## Components

Four independent building blocks. The default `generate_cac_canary.py`
workflow stitches them into a single planted folder, but each beacon
vector is conceptually separable:

1. **CAC-style credential canary** — three-cert PFX bundle (Identity
   with `clientAuth + smartcardLogon`, Digital Signature, Encryption)
   plus a synthetic CA chain that internally validates. Cert
   validation beacons fire on AIA OCSP, AIA caIssuers, and CRL
   distribution point fetches.
2. **DOCX template beacon** — minimal Word document whose
   `attachedTemplate` relationship points at the listener. Word
   fetches the URL when the document is opened. Available as
   `generate_docx_beacon.py` (standalone, with `--text` for custom
   body content) and shipped as `CAC Reset Procedure.docx` inside the
   CAC bundle by default.
3. **PDF open-action beacon** — minimal PDF with `/OpenAction /URI`
   pointing at the listener. The reader fetches the URL on document
   open (modern Acrobat prompts; many users click through). Available
   as `generate_pdf_beacon.py` (standalone, with `--text`) and
   shipped as `PIN Reset Instructions.pdf` inside the CAC bundle.
4. **Listener + S3 archive + replay tool** —
   - `canary_listener.py` routes path-encoded beacons (`/v/<token>/...`)
     and optionally archives to S3.
   - `read_events.py` pulls events for a token out of S3 and prints a
     pretty timeline (or NDJSON).

Shared helpers (URL builders, public-canary blocklist, file writers)
live in `beacons.py`.

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
| `CAC Reset Procedure.docx`    | Word `attachedTemplate` beacon (fires on open)   |
| `PIN Reset Instructions.pdf`  | PDF `/OpenAction /URI` beacon                    |

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

The leaves are signed by the bundled synthetic intermediate, which is
itself signed by a synthetic root with `CN=DoD Root CA 3`. The chain
validates internally — `openssl verify -CAfile DoD_CA_Bundle.pem
<leaf>.cer` succeeds — but the synthetic root is not the real DoD
root, so the cert will not authenticate to any system that already
trusts the actual DoD roots. That's the safety guarantee.

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

Each cert carries beacon URIs in its AIA and CRL extensions. They
fire when something tries to *validate or use* the credential, and
the listener attributes the hit to the specific cert (id/sig/enc):

| Filename                    | Channel | Trigger                                |
| --------------------------- | ------- | -------------------------------------- |
| `ocsp`                      | `ocsp`  | OCSP revocation check                  |
| `DODIDCA-59_IT.p7c`         | `aia`   | AIA caIssuers chain-build fetch        |
| `DODIDCA59.crl`             | `crl`   | CRL-based revocation check             |

Importing the `.pfx` into a cert store typically isn't enough on its
own — these wait for the *first use* of the cert. To fingerprint the
*finder* the moment the bundle is opened, see Layer 2.

### Layer 2 — honeyfolder (fire-on-browse / fire-on-open)

Four companion files give the operator multiple vectors that beacon
the moment the folder is browsed or a file is opened (unless
`--no-companions`):

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
- **`CAC Reset Procedure.docx`** — opens in Word. The DOCX has an
  `attachedTemplate` relationship pointing at
  `/v/<token>/template.dotx` (channel `tmpl`). Word fetches the URL
  to apply the template. Modern Office may show a security warning
  before fetching; many users click through, and even a blocked fetch
  often leaves a network-layer signal.
- **`PIN Reset Instructions.pdf`** — opens in a PDF reader. The PDF's
  `/OpenAction` is a URI action pointing at `/v/<token>/pdf-open`
  (channel `pdf`). Modern Acrobat Reader prompts before fetching;
  some third-party viewers and older Reader versions fetch silently.

Every request also logs source IP and full request headers
(`Accept-Language` is gold for locale, `User-Agent` for OS+browser),
so even hits that never reach the JS layer carry useful signal.

## Deployment

For a real engagement you want the listener running as a long-lived
service backed by S3 archival, with alerts wired to Slack (or
similar). The repo ships three pieces for that:

### AWS infrastructure (`infra/terraform/`)

```sh
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars        # bucket_name, listener_principals, analyst_principals
terraform init && terraform apply
terraform output bucket_name
```

Provisions:
- KMS-encrypted, versioned, public-blocked S3 bucket
- Lifecycle: events → Glacier IR at 30d, expire at 1y; scanner
  traffic in `unknown/` expires at 90d
- Writer role (`s3:PutObject` only) for the listener
- Reader role (`s3:ListBucket` + `s3:GetObject` on `events/*`) for
  analyst tooling

See [`infra/terraform/README.md`](infra/terraform/README.md) for
sizing and trade-off notes.

### Listener container

```sh
# Build + run with one command
docker compose up -d

# .env should contain:
#   CANARY_BUCKET=my-canary-archive
#   CANARY_PREFIX=canary
#   AWS_REGION=us-east-1
#   SLACK_WEBHOOK=https://hooks.slack.com/services/...   (optional)
```

The image is minimal: Python 3.11 + boto3, runs as a non-root user,
TCP-level healthcheck (no `/healthz` route — that would be a tell).
Front it with Caddy / ALB+ACM / Cloudflare for TLS; the listener
itself binds plain HTTP.

### Alerts (`--webhook-url`)

The listener has a third sink alongside stdout and S3: any URL you
pass to `--webhook-url` gets a JSON POST per matching event.

```sh
python canary_listener.py --port 8080 \
  --s3-bucket my-canary-archive --s3-prefix demo \
  --webhook-url https://hooks.slack.com/services/T00/B00/XXX \
  --webhook-format slack
```

`--webhook-format slack` produces an incoming-webhook-shaped
`{"text": "..."}` body with the token, source IP, channel, and (for
fingerprint events) UA + timezone + screen + GPU + hardware in
bullet form. `--webhook-format generic` POSTs the raw event JSON for
custom alert pipelines (PagerDuty Events API, your own router, etc.).

By default every channel except `unknown` is forwarded. Tighten with
`--webhook-channels fingerprint,urlclick,page,id/ocsp` or open up to
scanner traffic with `--webhook-include-unknown`.

POSTs run on per-event daemon threads with a 5s timeout — a slow
webhook can't stall the request handler.

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

### Standalone document beacons

The DOCX and PDF beacons can be generated on their own when you don't
want a fake CAC alongside them — useful for planting in non-CAC
contexts like an HR share, finance directory, or developer wiki.

```sh
# DOCX with custom body text
python generate_docx_beacon.py \
  --beacon-url https://pki-status.lab.example \
  --output "./Q3 Strategy.docx" \
  --text "Q3 Strategy — Confidential
Revenue targets, cost cuts, and reorg plan.
For executive review only."

# PDF with custom body text
python generate_pdf_beacon.py \
  --beacon-url https://pki-status.lab.example \
  --output "./Compensation_Q4.pdf" \
  --text "Compensation Review — Q4
Name: Doe, John
Salary: \$XXX,XXX"
```

Each prints `wrote / token / beacon` on stdout — record the token in
your deception inventory so you can map a hit back to the deployment
location. Supply `--token <T>` to reuse an existing token (handy when
you're planting a coordinated set of artifacts that share attribution).

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

Internet scanner traffic on unrecognised paths (channel `unknown`) is
archived separately at `<prefix>/unknown/<YYYY>/<MM>/<DD>/...` so it
doesn't pollute per-token analysis. Inspect with
`aws s3 ls s3://<bucket>/<prefix>/unknown/` when you want to see what
the listener's been probed with.

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

Sample timeline from a successful red-team trip (with geo enrichment
enabled — see below):

```
token: 9ZWvvBvh_99_Pi5s
events: 6  channels: fingerprint=1, icon=1, id/aia=1, id/ocsp=1, img=1, sig/ocsp=1
sources:
  10.0.5.42       hits=3 (Tysons Corner, VA, US — Comcast Cable, AS7922)
  52.94.10.5      hits=2 (Ashburn, VA, US — Amazon.com, AS16509)
  18.205.99.12    hits=1 (Ashburn, VA, US — Amazon.com, AS14618)

  10:25:41  [icon          ] 10.0.5.42        Mozilla/5.0 (Windows NT 10.0; Win64; x64)
                                 geo: (Tysons Corner, VA, US — Comcast, AS7922)
  10:25:42  [fingerprint   ] 10.0.5.42
      = Windows 10/11 / Edge 121 / Intel UHD Graphics 630 / 8 cores / 16 GB / en-US / America/Los_Angeles / 1920x1080
      ua                 Mozilla/5.0 ... Edg/121
      ... (full key/value detail still rendered below) ...
  11:42:10  [id/ocsp       ] 52.94.10.5       Microsoft-CryptoAPI/10.0
                                 geo: (Ashburn, VA, US — Amazon.com, AS16509)
  11:42:11  [id/aia        ] 52.94.10.5       Microsoft-CryptoAPI/10.0
  13:01:00  [sig/ocsp      ] 18.205.99.12     Mozilla/5.0 (Macintosh; Intel Mac OS X 14)
```

Reads: operator browsed the folder on Windows from a Comcast IP in
Tysons Corner at 10:25 (icon hit, then HTML opened — full Windows
fingerprint captured, summarised on the `=` line). Imported the ID
cert and tried to use it ~80 minutes later from an AWS egress
(Microsoft CryptoAPI fired our OCSP+AIA), and at 13:01 a different
AWS IP probed the SIG cert from a Mac. Three IPs, three behaviors,
all linked by the same token.

### Geo enrichment

Pass `--geo-db` and/or `--asn-db` pointing at MaxMind GeoLite2 .mmdb
files. The replay annotates every source IP with city/region/country
and ASN/org. GeoLite2 is free with a MaxMind account; install the
optional dependency with `pip install maxminddb`.

```sh
python read_events.py --bucket my-canary-archive --prefix demo --token <T> \
  --geo-db ./GeoLite2-City.mmdb \
  --asn-db ./GeoLite2-ASN.mmdb
```

Without the `.mmdb` files (or with `maxminddb` not installed) the
replay still works and just renders source IPs without geo.

### Fingerprint synthesis

Each `fingerprint` event renders a one-line summary above the full
key/value detail:

```
= Windows 10/11 / Edge 121 / Intel UHD Graphics 630 / 8 cores / 16 GB / en-US / America/Los_Angeles / 1920x1080
```

Built from the existing payload: UA → OS + browser, WebGL renderer
→ GPU, plus the `hwConcurrency` / `deviceMemory` / `languages` /
`tz` / `screen` fields. The full key/value block is still printed
below for the deep dive.

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

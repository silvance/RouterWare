# Terraform — bucket + KMS + IAM for the canary archive

Provisions everything the listener needs on the AWS side. Typically
run once per environment.

## What it creates

- An S3 bucket (private, versioned, KMS-encrypted)
- A customer-managed KMS key with rotation enabled
- A lifecycle policy:
  - `<prefix>/events/*` → Glacier IR at 30 days, expire at 1 year
  - `<prefix>/unknown/*` → expire at 90 days (no Glacier; scanner traffic)
- *(Optional)* a `listener-writer` IAM role with `s3:PutObject` only
- *(Optional)* an `analyst-reader` IAM role with `s3:ListBucket` +
  `s3:GetObject` scoped to `events/` (deliberately not `unknown/`)

The two roles are created only if you supply `listener_principals` /
`analyst_principals`. Otherwise the bucket + KMS are provisioned and
you wire policies to your existing roles however you do that.

## Usage

```sh
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars        # set bucket_name + principals

terraform init
terraform plan
terraform apply
```

Outputs you'll want afterwards:

```sh
terraform output bucket_name        # → pass to listener as --s3-bucket
terraform output writer_role_arn    # → attach to listener host/task
terraform output reader_role_arn    # → assume from analyst tooling
```

## Sizing the lifecycle

Defaults assume a low-volume deception program (a few engagements per
quarter, hits in the hundreds-to-thousands per token). If you run
high-volume honeyfile programs:

- Push `events_glacier_days` down to `7`
- Keep `events_expire_days` at `365` for compliance/forensics
- `unknown_expire_days` can stay at `90`; S3 Standard for short-lived
  noise is fine (Glacier IR has a 90-day minimum charge so it's not
  a win for short-retention objects)

## What it intentionally does NOT do

- Provision the listener host/container (use `Dockerfile` +
  `docker-compose.yml` at the repo root, or your own infra)
- Configure DNS / TLS termination (depends on your fronting setup —
  Caddy, ALB+ACM, Cloudflare)
- Set up alerting destinations (the listener emits webhook events
  via `--webhook-url`; the destination is yours)
- Manage analyst SSO/IAM-Identity-Center (the reader role just trusts
  whatever principals you list)

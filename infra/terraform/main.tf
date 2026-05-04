# --------------------------------------------------------------------
# KMS key for at-rest encryption
# --------------------------------------------------------------------

resource "aws_kms_key" "canary" {
  description             = "Encryption for ${var.bucket_name} (RouterWare canary archive)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_kms_alias" "canary" {
  name          = "alias/${var.bucket_name}"
  target_key_id = aws_kms_key.canary.id
}

# --------------------------------------------------------------------
# Bucket -- private, versioned, KMS-encrypted, lifecycle-managed
# --------------------------------------------------------------------

resource "aws_s3_bucket" "archive" {
  bucket = var.bucket_name
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "archive" {
  bucket = aws_s3_bucket.archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket                  = aws_s3_bucket.archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.canary.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  # Real beacon traffic: keep recent hits hot, push old hits to
  # Glacier IR for forensics, expire eventually.
  rule {
    id     = "events-glacier-then-expire"
    status = "Enabled"
    filter {
      prefix = "${var.prefix}/events/"
    }
    transition {
      days          = var.events_glacier_days
      storage_class = "GLACIER_IR"
    }
    expiration {
      days = var.events_expire_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  # Scanner / probe traffic: shorter retention, no Glacier (value
  # decays fast and Glacier has a 90-day minimum charge).
  rule {
    id     = "unknown-expire-quickly"
    status = "Enabled"
    filter {
      prefix = "${var.prefix}/unknown/"
    }
    expiration {
      days = var.unknown_expire_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# --------------------------------------------------------------------
# Listener writer role -- s3:PutObject only on this bucket+prefix
# --------------------------------------------------------------------

resource "aws_iam_role" "listener_writer" {
  count = length(var.listener_principals) > 0 ? 1 : 0
  name  = "${var.bucket_name}-listener-writer"
  tags  = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.listener_principals }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "listener_writer" {
  count = length(var.listener_principals) > 0 ? 1 : 0
  name  = "canary-write"
  role  = aws_iam_role.listener_writer[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PutEvents"
        Effect = "Allow"
        Action = "s3:PutObject"
        Resource = [
          "${aws_s3_bucket.archive.arn}/${var.prefix}/events/*",
          "${aws_s3_bucket.archive.arn}/${var.prefix}/unknown/*",
        ]
      },
      {
        Sid      = "HeadBucketForStartupCheck"
        Effect   = "Allow"
        Action   = "s3:HeadBucket"
        Resource = aws_s3_bucket.archive.arn
      },
      {
        Sid      = "EncryptWithKMS"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Encrypt"]
        Resource = aws_kms_key.canary.arn
      },
    ]
  })
}

# --------------------------------------------------------------------
# Analyst reader role -- ListBucket + GetObject on events/ only
# --------------------------------------------------------------------
#
# Deliberately scoped to events/, NOT unknown/. Scanner traffic in
# unknown/ may contain hostile payloads; analysts who need it can
# request a separate, narrower grant.

resource "aws_iam_role" "analyst_reader" {
  count = length(var.analyst_principals) > 0 ? 1 : 0
  name  = "${var.bucket_name}-analyst-reader"
  tags  = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.analyst_principals }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "analyst_reader" {
  count = length(var.analyst_principals) > 0 ? 1 : 0
  name  = "canary-read"
  role  = aws_iam_role.analyst_reader[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListEvents"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.archive.arn
        Condition = {
          StringLike = {
            "s3:prefix" = ["${var.prefix}/events/*"]
          }
        }
      },
      {
        Sid      = "ReadEvents"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.archive.arn}/${var.prefix}/events/*"
      },
      {
        Sid      = "DecryptKMS"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.canary.arn
      },
    ]
  })
}

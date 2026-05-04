output "bucket_name" {
  value       = aws_s3_bucket.archive.id
  description = "Pass to the listener as --s3-bucket."
}

output "bucket_arn" {
  value = aws_s3_bucket.archive.arn
}

output "kms_key_arn" {
  value = aws_kms_key.canary.arn
}

output "writer_role_arn" {
  value       = try(aws_iam_role.listener_writer[0].arn, null)
  description = "Attach to the listener's instance profile / task role. null if listener_principals was empty."
}

output "reader_role_arn" {
  value       = try(aws_iam_role.analyst_reader[0].arn, null)
  description = "Assume from analyst tooling. null if analyst_principals was empty."
}

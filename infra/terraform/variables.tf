variable "bucket_name" {
  type        = string
  description = "S3 bucket name for the canary archive. Must be globally unique."
}

variable "prefix" {
  type        = string
  default     = "canary"
  description = "Key prefix inside the bucket. Matches the listener's --s3-prefix."
}

variable "events_glacier_days" {
  type        = number
  default     = 30
  description = "Days after which events/* objects transition to Glacier IR."
}

variable "events_expire_days" {
  type        = number
  default     = 365
  description = "Days after which events/* objects are deleted."
}

variable "unknown_expire_days" {
  type        = number
  default     = 90
  description = "Days after which unknown/* (scanner traffic) is deleted. Shorter than events because the value-per-byte is lower."
}

variable "listener_principals" {
  type        = list(string)
  default     = []
  description = "ARNs (account roots, role ARNs, service principals) allowed to assume the writer role. Empty list disables creation of the writer role -- attach an inline policy to your existing instance/task role instead."
}

variable "analyst_principals" {
  type        = list(string)
  default     = []
  description = "ARNs allowed to assume the reader role. Typically your SSO permission-set ARN or a specific user/role for analysts. Empty list disables creation."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to every resource."
}

variable "environment" {
  description = "Environment name (e.g. staging, production)"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "tre_message_topic_arn" {
  description = <<-EOT
    SNS topic ARN that publishes TRE messages (envelope shape:
    `{ "properties": { "messageType": "..." }, ... }`).
    The subscription to this topic is filtered to only deliver
    `CourtDocumentPackageAvailable` messages to the ingest queue.
  EOT
  type        = string
}

variable "bulk_ingest_s3_event_topic_arn" {
  description = <<-EOT
    SNS topic ARN that fans out raw S3 event notifications
    (envelope shape: `{ "Records": [ { "eventName": "ObjectCreated:*", "s3": {...} } ] }`).
    The subscription to this topic is filtered to only deliver
    `ObjectCreated:*` events to the ingest queue.
  EOT
  type        = string
}

variable "message_retention_seconds" {
  description = "How long messages are retained in the ingest queue (max 1209600 = 14 days)"
  type        = number
  default     = 1209600
}

variable "visibility_timeout_seconds" {
  description = "SQS visibility timeout. Must be >= 6x the Lambda timeout (420s). Default 2520s."
  type        = number
  default     = 2520
}

variable "max_receive_count" {
  description = "Number of times a message can be received before being sent to the DLQ"
  type        = number
  default     = 1
}

variable "tags" {
  description = "Tags to apply to all resources, e.g. { Project = \"ds-caselaw-ingester\" }"
  type        = map(string)
  default     = {}
}

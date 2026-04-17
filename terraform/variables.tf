variable "environment" {
  description = "Environment name (e.g. staging, production)"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "sns_topic_arns" {
  description = "List of SNS topic ARNs that publish ingest messages (owned by another team)"
  type        = list(string)
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
  default     = 5
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

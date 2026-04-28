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

# --- CloudWatch alarm thresholds (see alarms.tf) ---

variable "ingest_queue_oldest_message_age_threshold_seconds" {
  description = <<-EOT
    Threshold in seconds for the ingest queue ApproximateAgeOfOldestMessage alarm.
    Default 600s (10 minutes) — comfortably above the 420s Lambda timeout, so
    transient single-message slowness doesn't fire, but a real backlog does.
  EOT
  type        = number
  default     = 600
}

variable "ingest_queue_oldest_message_age_evaluation_periods" {
  description = "Number of consecutive 1-minute periods the oldest-message-age alarm must breach before firing."
  type        = number
  default     = 5
}

variable "ingest_queue_dlq_oldest_message_age_threshold_seconds" {
  description = <<-EOT
    Threshold in seconds for the ingest DLQ ApproximateAgeOfOldestMessage alarm.
    Default 3600s (1 hour) — DLQ messages should be triaged well before the
    14-day retention window expires.
  EOT
  type        = number
  default     = 3600
}

# --- Lambda alarm configuration (see alarms.tf) ---
#
# The ingester Lambda itself is currently provisioned by SAM (`template.yml`),
# but its CloudWatch alarms are owned here. SAM auto-generates the function
# name as `<sam-stack-name>-TNACaselawIngesterFunction-<hash>` (the hash
# differs per environment), so the resolved name must be supplied here as a
# per-environment secret rather than computed from the stack name.

variable "lambda_function_name" {
  description = <<-EOT
    Name of the existing ingester Lambda function (used as the `FunctionName`
    dimension for CloudWatch alarms). Look this up in the AWS console for each
    environment — SAM auto-generates it as
    `<sam-stack-name>-TNACaselawIngesterFunction-<hash>` and the hash differs
    between environments. When the Lambda is migrated from SAM into this
    Terraform stack, this variable can be removed and replaced with a direct
    resource reference.
  EOT
  type        = string
}

variable "lambda_timeout_seconds" {
  description = "The Lambda function's configured timeout. Used to set the Duration alarm threshold (default = 80% of this)."
  type        = number
  default     = 420
}

variable "lambda_reserved_concurrency" {
  description = <<-EOT
    Optional reserved concurrency configured for the ingester Lambda. If set
    (>0), the ConcurrentExecutions alarm fires at 90% of this value. If 0 or
    null, the alarm is sized against `region_level_concurrency_limit` instead.
  EOT
  type        = number
  default     = 0
}

variable "region_level_concurrency_limit" {
  description = "Account+region Lambda unreserved concurrency limit. Used by the ClaimedAccountConcurrency alarm (fires at 90%)."
  type        = number
  default     = 1000
}

# --- Slack alarm delivery (see slack_alarms.tf) ---

variable "slack_channel_id" {
  description = <<-EOT
    Slack channel ID (NOT the channel name) that CloudWatch alarm
    notifications will be posted to via EventBridge -> Slack chat.postMessage.
    Example: "C0123456789". The bot whose token is stored in the
    `<env>-caselaw-ingester-alarms-slack-token` Secrets Manager secret must be
    invited to this channel.

    No default — must be provided per environment (e.g. via tfvars / CI
    secret) so the channel ID isn't committed to this public repo.
  EOT
  type        = string
  sensitive   = true
}

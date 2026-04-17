# SQS Ingest Queue with DLQ using shared DA Terraform modules.
# Provides durable buffering between the ingest SNS topic(s) and the ingester Lambda.
module "ingest_queue" {
  source = "github.com/nationalarchives/da-terraform-modules//sqs?ref=95a628ab6aeb8435cbee1351c4b3c0e82ca4bde0"

  queue_name = "${var.environment}-caselaw-ingest-queue"

  # DLQ — messages move here after max retries exhausted
  create_dlq               = true
  redrive_maximum_receives = var.max_receive_count

  # Visibility timeout must be >= 6× Lambda timeout (420s) to prevent
  # premature re-delivery while Lambda is still processing.
  visibility_timeout = var.visibility_timeout_seconds

  # Keep messages for up to 14 days (maximum SQS retention)
  message_retention_seconds = var.message_retention_seconds

  # Encryption — SSE-SQS (no KMS key needed for this queue)
  encryption_type = "sse"

  # Enable long polling to reduce empty-receive costs
  receive_wait_time_seconds = 20

  # SQS policy — allow the ingest SNS topic(s) to send messages,
  # and deny unencrypted transport.
  sqs_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSNSPublish"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = "*"
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = var.sns_topic_arns
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "sqs:*"
        Resource  = "*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Environment = var.environment
    Purpose     = "Durable ingest message buffer with retry and DLQ"
  })
}

# Subscribe the SQS queue to each SNS topic.
# This requires sns:Subscribe permission on the topic. If the topic is in
# another account or you lack permission, remove this resource and ask the
# topic owner to create the subscription pointing at the queue ARN in outputs.
resource "aws_sns_topic_subscription" "ingest_queue_subscription" {
  for_each = toset(var.sns_topic_arns)

  topic_arn            = each.value
  protocol             = "sqs"
  endpoint             = module.ingest_queue.sqs_arn
  raw_message_delivery = false # Preserve SNS envelope for auditability
}

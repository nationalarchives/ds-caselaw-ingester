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
            "aws:SourceArn" = [var.tre_message_topic_arn, var.bulk_ingest_s3_event_topic_arn]
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

# Subscriptions to TRE message topics.
#
# These topics carry application-level TRE messages with a `properties.messageType`
# discriminator. Only `CourtDocumentPackageAvailable` messages are delivered to
# the ingest queue; all other message types are dropped at the SNS layer.
#
# Requires sns:Subscribe permission on each topic. If the topic is in another
# account or you lack permission, remove this resource and ask the topic owner
# to create the subscription pointing at the queue ARN in outputs.
resource "aws_sns_topic_subscription" "tre_message_subscription" {
  topic_arn            = var.tre_message_topic_arn
  protocol             = "sqs"
  endpoint             = module.ingest_queue.sqs_arn
  raw_message_delivery = false # Preserve SNS envelope for auditability

  filter_policy_scope = "MessageBody"
  filter_policy = jsonencode({
    properties = {
      messageType = [
        "uk.gov.nationalarchives.da.messages.courtdocumentpackage.available.CourtDocumentPackageAvailable",
      ]
    }
  })
}

# Subscriptions to SNS topics that fan out raw S3 event notifications.
#
# S3 event payloads use a different envelope (`Records[].eventName`), so they
# need a distinct filter policy. The `prefix` match covers all `ObjectCreated:*`
# variants (Put, Post, Copy, CompleteMultipartUpload) so multipart uploads are
# not silently dropped.
resource "aws_sns_topic_subscription" "bulk_ingest_s3_event_subscription" {
  topic_arn            = var.bulk_ingest_s3_event_topic_arn
  protocol             = "sqs"
  endpoint             = module.ingest_queue.sqs_arn
  raw_message_delivery = false # Preserve SNS envelope for auditability

  filter_policy_scope = "MessageBody"
  filter_policy = jsonencode({
    Records = {
      eventName = [{ prefix = "ObjectCreated:" }]
    }
  })
}

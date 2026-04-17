output "ingest_queue_arn" {
  description = "ARN of the SQS ingest queue (pass to SAM template as IngestQueueArn)"
  value       = module.ingest_queue.sqs_arn
}

output "ingest_queue_url" {
  description = "URL of the SQS ingest queue"
  value       = module.ingest_queue.sqs_queue_url
}

output "ingest_dlq_arn" {
  description = "ARN of the SQS dead-letter queue"
  value       = module.ingest_queue.dlq_sqs_arn
}

output "ingest_dlq_url" {
  description = "URL of the SQS dead-letter queue"
  value       = module.ingest_queue.dlq_sqs_url
}

output "cloudwatch_alarm_arns" {
  description = "ARNs of the CloudWatch alarms for queue monitoring"
  value       = module.ingest_queue.alarms
}

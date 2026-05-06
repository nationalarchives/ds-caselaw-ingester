output "ingest_queue_arn" {
  description = "ARN of the SQS ingest queue"
  value       = module.ingest_queue.sqs_arn
}

output "ingest_queue_url" {
  description = "URL of the SQS ingest queue"
  value       = module.ingest_queue.sqs_queue_url
}

output "ingest_queue_dlq_arn" {
  description = "ARN of the SQS ingest dead-letter queue"
  value       = module.ingest_queue.dlq_sqs_arn
}

output "ingest_queue_dlq_url" {
  description = "URL of the SQS ingest dead-letter queue"
  value       = module.ingest_queue.dlq_sqs_url
}

output "ingest_queue_alarm_arns" {
  description = "ARNs of the CloudWatch alarms for the ingest queue"
  value       = module.ingest_queue.alarms
}

output "codeguru_profiling_group_arn" {
  description = "ARN of the CodeGuru Profiler profiling group for the ingester Lambda"
  value       = aws_codeguruprofiler_profiling_group.ingester.arn
}

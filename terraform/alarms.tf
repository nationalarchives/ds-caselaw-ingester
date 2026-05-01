# CloudWatch alarms for resources managed by this Terraform stack.
#
# Following AWS recommended best-practice alarms:
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Best_Practice_Recommended_Alarms_AWS_Services.html
#
# Scope of this file:
#   - SQS ingest queue + DLQ (managed here via the da-terraform-modules/sqs module)
#   - Ingester Lambda (the function itself is provisioned by SAM in
#     `template.yml`, but its alarms are owned here. The function name is
#     pinned in SAM and passed in via `var.lambda_function_name`.)
#
# The shared SQS module, as specified in main.tf, already creates the following alarms for us, so they are
# intentionally NOT redefined here:
#   - <queue>-messages-visible-alarm           (ApproximateNumberOfMessagesVisible on main queue)
#   - <queue>-dlq-messages-visible-alarm       (ApproximateNumberOfMessagesVisible on DLQ)
#   - <queue>-dlq-new-messages-added-alarm     (change in total DLQ messages, i.e. diff of ApproximateNumberOfMessagesVisible and ApproximateNumberOfMessagesNotVisible combined)
#   - <queue>-unprocessed-messages-alert       (ApproximateNumberOfMessagesVisible > 0 but NumberOfMessagesReceived is 0, i.e. messages are waiting but no consumer is polling)
#
# The alarms below cover the remaining AWS-recommended SQS and Lambda alarms,
# matching the actions_enabled=false / empty-actions style used elsewhere in
# this account until SNS wiring is added.
#
# Follow-up (SQS): the three SQS alarms defined here (oldest-message-age on
# the main queue and DLQ, plus messages-sent on the DLQ) are AWS-recommended
# best-practice alarms that every consumer of the shared SQS module would
# benefit from. Consider upstreaming them into
# `nationalarchives/da-terraform-modules//sqs` so they're created
# automatically alongside the existing module-managed alarms, and this file
# can drop the SQS section entirely.
#
# Follow-up (Lambda): migrate the Lambda itself from SAM (`template.yml`)
# into this Terraform stack so the function and its alarms are co-located.

locals {
  ingest_queue_name     = "${var.environment}-caselaw-ingest-queue"
  ingest_queue_dlq_name = "${local.ingest_queue_name}-dlq"
}

# ApproximateAgeOfOldestMessage — main ingest queue.
#
# This alarm helps to detect when consumers are not processing messages from
# the queue fast enough (e.g. Lambda is throttled, failing, or downstream
# MarkLogic is slow). A growing oldest-message age is the canonical SQS
# back-pressure signal.
#
# Threshold rationale: the Lambda timeout is 420s and visibility timeout is
# 2520s (6× Lambda). If a message has been sitting visible for longer than the
# Lambda timeout, processing is almost certainly falling behind.
resource "aws_cloudwatch_metric_alarm" "ingest_queue_oldest_message_age" {
  alarm_name        = "${local.ingest_queue_name}-oldest-message-age-alarm"
  alarm_description = "Triggers when the oldest message in the ingest queue has been waiting longer than expected. Indicates the Lambda consumer is falling behind (throttled, failing, or downstream slow). Investigate Lambda errors/throttles and downstream (MarkLogic) latency."

  actions_enabled           = false
  treat_missing_data        = "notBreaching"
  ok_actions                = []
  alarm_actions             = []
  insufficient_data_actions = []

  namespace   = "AWS/SQS"
  metric_name = "ApproximateAgeOfOldestMessage"
  statistic   = "Maximum"
  dimensions = {
    QueueName = local.ingest_queue_name
  }

  period              = 60
  evaluation_periods  = var.ingest_queue_oldest_message_age_evaluation_periods
  datapoints_to_alarm = var.ingest_queue_oldest_message_age_evaluation_periods
  threshold           = var.ingest_queue_oldest_message_age_threshold_seconds
  comparison_operator = "GreaterThanThreshold"
}

# ApproximateAgeOfOldestMessage — DLQ.
#
# AWS recommends alarming on DLQ oldest-message age so failed messages don't
# silently age out of the 14-day retention window without being investigated.
resource "aws_cloudwatch_metric_alarm" "ingest_queue_dlq_oldest_message_age" {
  alarm_name        = "${local.ingest_queue_dlq_name}-oldest-message-age-alarm"
  alarm_description = "Triggers when a message has been sitting in the ingest DLQ for longer than expected. DLQ messages indicate failed ingestions that need manual review before they age out of retention (14 days)."

  actions_enabled           = false
  treat_missing_data        = "notBreaching"
  ok_actions                = []
  alarm_actions             = []
  insufficient_data_actions = []

  namespace   = "AWS/SQS"
  metric_name = "ApproximateAgeOfOldestMessage"
  statistic   = "Maximum"
  dimensions = {
    QueueName = local.ingest_queue_dlq_name
  }

  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = var.ingest_queue_dlq_oldest_message_age_threshold_seconds
  comparison_operator = "GreaterThanThreshold"
}

# NumberOfMessagesSent — DLQ.
#
# AWS recommends alarming on any send to the DLQ so that even a single failed
# message is surfaced promptly. The module's `new_messages_added_to_dlq_alert`
# uses a DIFF expression which can miss cases where a message arrives and is
# immediately re-driven; this alarm provides direct coverage.
resource "aws_cloudwatch_metric_alarm" "ingest_queue_dlq_messages_sent" {
  alarm_name        = "${local.ingest_queue_dlq_name}-messages-sent-alarm"
  alarm_description = "Triggers when one or more messages are sent to the ingest DLQ within the evaluation period. Any DLQ delivery indicates an ingestion failure that exhausted retries."

  actions_enabled           = false
  treat_missing_data        = "notBreaching"
  ok_actions                = []
  alarm_actions             = []
  insufficient_data_actions = []

  namespace   = "AWS/SQS"
  metric_name = "NumberOfMessagesSent"
  statistic   = "Sum"
  dimensions = {
    QueueName = local.ingest_queue_dlq_name
  }

  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
}

# -----------------------------------------------------------------------------
# Lambda alarms (function provisioned by SAM, alarms owned here).
# AWS recommended alarms:
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Best_Practice_Recommended_Alarms_AWS_Services.html#Lambda
# -----------------------------------------------------------------------------

locals {
  # If a reserved concurrency is configured, scale the per-function concurrency
  # alarm against it; otherwise fall back to the account/region limit.
  lambda_concurrency_alarm_threshold = var.lambda_reserved_concurrency > 0 ? (
    0.9 * var.lambda_reserved_concurrency
    ) : (
    0.9 * var.region_level_concurrency_limit
  )
}

# Errors — any function error indicates an ingestion failure.
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name        = "${var.lambda_function_name}-errors-alarm"
  alarm_description = "Triggers when the ingester Lambda reports any errors. Each error corresponds to a failed ingestion that will be retried via SQS and may end up in the DLQ. Investigate Lambda logs and Rollbar."

  actions_enabled           = false
  treat_missing_data        = "notBreaching"
  ok_actions                = []
  alarm_actions             = []
  insufficient_data_actions = []

  namespace   = "AWS/Lambda"
  metric_name = "Errors"
  statistic   = "Sum"
  dimensions = {
    FunctionName = var.lambda_function_name
  }

  period              = 60
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
}

# Throttles — invocations rejected because concurrency limit was hit.
# With `max_receive_count = 1` on the queue, a throttle goes straight to the DLQ.
resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  alarm_name        = "${var.lambda_function_name}-throttles-alarm"
  alarm_description = "Triggers when the ingester Lambda is throttled. Given max_receive_count=1 on the ingest queue, throttled messages go straight to the DLQ. Consider raising MaximumConcurrency or the account concurrency limit."

  actions_enabled           = false
  treat_missing_data        = "notBreaching"
  ok_actions                = []
  alarm_actions             = []
  insufficient_data_actions = []

  namespace   = "AWS/Lambda"
  metric_name = "Throttles"
  statistic   = "Sum"
  dimensions = {
    FunctionName = var.lambda_function_name
  }

  period              = 60
  evaluation_periods  = 5
  datapoints_to_alarm = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
}

# Duration — invocation runtime approaching the configured timeout.
# Threshold is set to 80% of the function timeout (in milliseconds).
resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  alarm_name        = "${var.lambda_function_name}-duration-alarm"
  alarm_description = "Triggers when the ingester Lambda's p95 duration exceeds 80% of its configured timeout. Indicates risk of timeouts and degraded throughput; investigate downstream (MarkLogic) latency."

  actions_enabled           = false
  treat_missing_data        = "notBreaching"
  ok_actions                = []
  alarm_actions             = []
  insufficient_data_actions = []

  namespace          = "AWS/Lambda"
  metric_name        = "Duration"
  extended_statistic = "p95"
  dimensions = {
    FunctionName = var.lambda_function_name
  }

  period              = 60
  evaluation_periods  = 15
  datapoints_to_alarm = 15
  threshold           = 0.8 * var.lambda_timeout_seconds * 1000
  comparison_operator = "GreaterThanThreshold"
}

# ConcurrentExecutions — function approaching its concurrency ceiling.
resource "aws_cloudwatch_metric_alarm" "lambda_concurrent_executions" {
  alarm_name        = "${var.lambda_function_name}-concurrent-executions-alarm"
  alarm_description = "Triggers when the ingester Lambda's concurrent executions approach 90% of its configured ceiling (reserved concurrency if set, otherwise the region-level limit). Throttling becomes likely soon after."

  actions_enabled           = false
  treat_missing_data        = "notBreaching"
  ok_actions                = []
  alarm_actions             = []
  insufficient_data_actions = []

  namespace   = "AWS/Lambda"
  metric_name = "ConcurrentExecutions"
  statistic   = "Maximum"
  dimensions = {
    FunctionName = var.lambda_function_name
  }

  period              = 60
  evaluation_periods  = 10
  datapoints_to_alarm = 10
  threshold           = local.lambda_concurrency_alarm_threshold
  comparison_operator = "GreaterThanThreshold"
}

# ClaimedAccountConcurrency — region-wide Lambda concurrency saturation.
# This is account-scoped (not function-scoped), but is recommended for any
# account that runs Lambda functions and is included here while the ingester
# is the primary Lambda workload in this stack.
resource "aws_cloudwatch_metric_alarm" "lambda_claimed_account_concurrency" {
  alarm_name        = "${var.environment}-caselaw-ingester-claimed-account-concurrency-alarm"
  alarm_description = "This alarm helps to monitor if the concurrency of your Lambda functions is approaching the Region-level concurrency limit of your account. A function starts to be throttled if it reaches the concurrency limit. You can take the following actions to avoid throttling. 1) Request a concurrency increase in this Region. 2) Identify and reduce any unused reserved concurrency or provisioned concurrency. 3) Identify performance issues in the functions to improve the speed of processing and therefore improve throughput. 4) Increase the batch size of the functions, so that more messages are processed by each function invocation."

  actions_enabled           = false
  treat_missing_data        = "notBreaching"
  ok_actions                = []
  alarm_actions             = []
  insufficient_data_actions = []

  namespace   = "AWS/Lambda"
  metric_name = "ClaimedAccountConcurrency"
  statistic   = "Maximum"
  dimensions  = {}

  period              = 60
  evaluation_periods  = 10
  datapoints_to_alarm = 10
  threshold           = 0.9 * var.region_level_concurrency_limit
  comparison_operator = "GreaterThanThreshold"
}

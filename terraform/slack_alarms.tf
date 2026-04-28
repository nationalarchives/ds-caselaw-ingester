# Slack delivery for CloudWatch alarms.
#
# Pattern adapted from da-ayr-terraform's `eventbridge_alarms` module
# (https://github.com/nationalarchives/da-ayr-terraform), but kept account-local
# — there is no shared management/observability account in Caselaw, so the
# whole pipeline is created inside this stack.
#
# Flow:
#   CloudWatch alarm state change
#     -> default event bus (automatic; no alarm_actions wiring needed)
#     -> EventBridge rule (filters to ALARM and OK transitions)
#     -> EventBridge API destination (HTTPS POST to Slack chat.postMessage)
#     -> Slack channel
#
# The Slack bot token is read from an AWS Secrets Manager secret. The secret is
# created here as an empty placeholder; populate the value once via the AWS
# console or a separate out-of-band process so the token isn't stored in
# Terraform state in plaintext.
#
# Required Slack bot scopes: `chat:write` (and the bot must be invited to the
# target channel).

locals {
  slack_alarm_states = toset(["ALARM", "OK"])
}

# Empty placeholder secret. Populate the bot token (raw `xoxb-...` string)
# via the AWS console after first apply. Subsequent applies will not overwrite
# the value because we don't manage `aws_secretsmanager_secret_version`.
resource "aws_secretsmanager_secret" "alarms_slack_token" {
  name        = "${var.environment}-caselaw-ingester-alarms-slack-token"
  description = "Slack bot token used by EventBridge to post CloudWatch alarm notifications. Populate manually after first apply."

  tags = var.tags
}

data "aws_secretsmanager_secret_version" "alarms_slack_token" {
  secret_id = aws_secretsmanager_secret.alarms_slack_token.id
}

resource "aws_cloudwatch_event_connection" "slack" {
  name               = "${var.environment}-caselaw-ingester-alarms-slack"
  description        = "Authorization header for Slack chat.postMessage (CloudWatch alarm notifications)"
  authorization_type = "API_KEY"

  auth_parameters {
    api_key {
      key   = "Authorization"
      value = "Bearer ${data.aws_secretsmanager_secret_version.alarms_slack_token.secret_string}"
    }
  }
}

resource "aws_cloudwatch_event_api_destination" "slack" {
  name                             = "${var.environment}-caselaw-ingester-alarms-slack"
  description                      = "Slack chat.postMessage endpoint for CloudWatch alarm notifications"
  invocation_endpoint              = "https://slack.com/api/chat.postMessage"
  http_method                      = "POST"
  invocation_rate_limit_per_second = 5
  connection_arn                   = aws_cloudwatch_event_connection.slack.arn
}

# IAM role allowing EventBridge to invoke the Slack API destination.
data "aws_iam_policy_document" "events_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "invoke_slack" {
  statement {
    sid       = "InvokeSlackApiDestination"
    effect    = "Allow"
    actions   = ["events:InvokeApiDestination"]
    resources = [aws_cloudwatch_event_api_destination.slack.arn]
  }
}

resource "aws_iam_role" "alarms_to_slack" {
  name               = "${var.environment}-caselaw-ingester-alarms-to-slack"
  assume_role_policy = data.aws_iam_policy_document.events_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "alarms_to_slack" {
  name   = "invoke-slack-api-destination"
  role   = aws_iam_role.alarms_to_slack.id
  policy = data.aws_iam_policy_document.invoke_slack.json
}

# Filter on alarm-name prefix so this rule only matches the ingester's alarms,
# not unrelated alarms that might be added to this account in future.
resource "aws_cloudwatch_event_rule" "alarm_state_change" {
  for_each    = local.slack_alarm_states
  name        = "${var.environment}-caselaw-ingester-alarm-${lower(each.key)}"
  description = "Forward CloudWatch alarm ${each.key} transitions for the ingester to Slack"

  event_pattern = jsonencode({
    source        = ["aws.cloudwatch"]
    "detail-type" = ["CloudWatch Alarm State Change"]
    detail = {
      state = {
        value = [each.key]
      }
      alarmName = [
        # All ingester alarms follow the `<resource-name>-...-alarm` naming
        # convention used by da-terraform-modules/sqs, so a small set of
        # prefixes covers every alarm in this stack:
        #   - `<env>-caselaw-ingest-queue-...`     (main queue: module + ours)
        #   - `<env>-caselaw-ingest-queue-dlq-...` (DLQ: module + ours)
        #   - `<lambda-function-name>-...`         (Lambda alarms)
        #   - `<env>-caselaw-ingester-...`         (account-scoped Lambda alarms)
        { prefix = "${local.ingest_queue_name}-" },
        { prefix = "${local.ingest_queue_dlq_name}-" },
        { prefix = "${var.lambda_function_name}-" },
        { prefix = "${var.environment}-caselaw-ingester-" },
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "alarm_state_change_to_slack" {
  for_each = local.slack_alarm_states
  rule     = aws_cloudwatch_event_rule.alarm_state_change[each.key].name
  arn      = aws_cloudwatch_event_api_destination.slack.arn
  role_arn = aws_iam_role.alarms_to_slack.arn

  input_transformer {
    input_paths = {
      alarmName = "$.detail.alarmName"
      resources = "$.resources[0]"
      state     = "$.detail.state.value"
      reason    = "$.detail.state.reason"
      time      = "$.detail.state.timestamp"
    }

    # Slack Web API payload. `channel` is the Slack channel ID (NOT the name).
    input_template = <<-JSON
      {
        "channel": "${var.slack_channel_id}",
        "text": "${each.key == "ALARM" ? ":helmet_with_white_cross:" : ":green-tick:"} *${var.environment} ingester* alarm <alarmName> -> ${each.key}\n*Resource:* <resources>\n*Time:* <time>\n*Reason:* <reason>"
      }
    JSON
  }
}

# NOTE: alarms intentionally keep `actions_enabled = false`. CloudWatch always
# emits state-change events to the default EventBridge bus regardless of that
# flag, so the rule above still fires; setting it true would (incorrectly)
# also try to fan out to non-existent SNS topics.

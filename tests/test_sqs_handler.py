import json
from unittest.mock import PropertyMock, patch

import pytest
from caselawclient.factories import IdentifierResolutionsFactory
from caselawclient.types import DocumentURIString

from src.ds_caselaw_ingester import exceptions, lambda_function

from .conftest import sqs_s3_event, sqs_v2_event, v2_message_raw
from .helpers import (
    assert_log_has_message_starting,
    assert_log_shows_successful_ingest,
    create_fake_bulk_file,
    create_fake_tdr_file,
)


class TestSQSHandler:
    """Tests for SQS event handling (SNS → SQS → Lambda path)."""

    @patch("src.ds_caselaw_ingester.lambda_function.api_client", autospec=True)
    @patch("src.ds_caselaw_ingester.lambda_function.s3_client")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_updated_judgment_notification")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_new_judgment_notification")
    @patch("src.ds_caselaw_ingester.ingester.VersionAnnotation")
    @patch("src.ds_caselaw_ingester.ingester.modify_filename")
    @patch("src.ds_caselaw_ingester.ingester.Document")
    @patch(
        "src.ds_caselaw_ingester.ingester.Ingest.find_existing_document_by_ncn",
        return_value=IdentifierResolutionsFactory.build(),
    )
    @patch(
        "src.ds_caselaw_ingester.ingester.Ingest.database_location",
        new_callable=PropertyMock,
        return_value=((DocumentURIString("cat"), True)),
    )
    def test_sqs_handler_v2_message(
        self,
        mock_database_location,
        mock_existing_uri,
        mock_doc,
        modify_filename,
        annotation,
        notify_new,
        notify_update,
        mock_s3_client,
        apiclient,
        caplog: pytest.LogCaptureFixture,
        handler_context,
    ):
        """Test that a V2 message arriving via SQS is processed correctly."""
        mock_s3_client.download_file = create_fake_tdr_file
        doc = apiclient.get_document_by_uri.return_value
        doc.neutral_citation = None
        mock_doc.return_value = doc

        result = lambda_function.handler(event=sqs_v2_event, context=handler_context)

        assert_log_shows_successful_ingest(caplog)
        notify_update.assert_called()
        notify_new.assert_not_called()
        # No failures → empty batchItemFailures
        assert result == {"batchItemFailures": []}

    @patch("src.ds_caselaw_ingester.lambda_function.api_client", autospec=True)
    @patch("src.ds_caselaw_ingester.lambda_function.s3_client")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_new_judgment_notification")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_updated_judgment_notification")
    @patch("src.ds_caselaw_ingester.ingester.VersionAnnotation")
    @patch("src.ds_caselaw_ingester.ingester.modify_filename")
    @patch("src.ds_caselaw_ingester.ingester.uuid4")
    @patch("src.ds_caselaw_ingester.ingester.Document")
    @patch(
        "src.ds_caselaw_ingester.ingester.Ingest.find_existing_document_by_ncn",
        return_value=IdentifierResolutionsFactory.build(),
    )
    @patch(
        "src.ds_caselaw_ingester.ingester.Ingest.database_location",
        new_callable=PropertyMock,
        return_value=(DocumentURIString("cat"), True),
    )
    def test_sqs_handler_s3_message(
        self,
        mock_determine,
        mock_existing,
        mock_doc,
        mock_uuid4,
        modify_filename,
        annotation,
        notify_new,
        notify_updated,
        mock_s3_client,
        apiclient,
        caplog: pytest.LogCaptureFixture,
        handler_context,
    ):
        """Test that an S3 message arriving via SQS is processed correctly."""
        mock_s3_client.download_file = create_fake_bulk_file
        mock_uuid4.return_value = "a1b2-c3d4"
        doc = apiclient.get_document_by_uri.return_value
        doc.neutral_citation = "[2012] UKUT 82 (IAC)"
        mock_doc.return_value = doc

        result = lambda_function.handler(event=sqs_s3_event, context=handler_context)

        assert_log_has_message_starting(caplog, "Ingester Start: Consignment reference BULK-0")
        assert_log_shows_successful_ingest(caplog)

        assert result == {"batchItemFailures": []}

    @patch("src.ds_caselaw_ingester.lambda_function.s3_client")
    @patch(
        "src.ds_caselaw_ingester.lambda_function.perform_ingest",
        side_effect=exceptions.FileNotFoundException("test-sqs-failure"),
    )
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest")
    @patch("src.ds_caselaw_ingester.lambda_function.rollbar.report_exc_info")
    @patch("src.ds_caselaw_ingester.lambda_function.api_client", autospec=True)
    def test_sqs_handler_returns_batch_item_failures(
        self,
        mock_api_client,
        mock_rollbar_call,
        mock_ingest,
        mock_perform_ingest,
        mock_s3_client,
        handler_context,
    ):
        """Failed SQS messages are reported as batchItemFailures so only they are retried."""
        result = lambda_function.handler(event=sqs_v2_event, context=handler_context)

        mock_rollbar_call.assert_called_with(level="error")
        assert result == {"batchItemFailures": [{"itemIdentifier": "msg-001"}]}

    @patch("src.ds_caselaw_ingester.lambda_function.s3_client")
    @patch(
        "src.ds_caselaw_ingester.lambda_function.perform_ingest",
        side_effect=[
            exceptions.FileNotFoundException("test"),
            None,  # second message succeeds
        ],
    )
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest")
    @patch("src.ds_caselaw_ingester.lambda_function.rollbar.report_exc_info")
    @patch("src.ds_caselaw_ingester.lambda_function.api_client", autospec=True)
    def test_sqs_handler_partial_batch_failure(
        self,
        mock_api_client,
        mock_rollbar_call,
        mock_ingest,
        mock_perform_ingest,
        mock_s3_client,
        handler_context,
    ):
        """When one message in a batch fails, only that message is reported as failed."""
        two_message_sqs_event = {
            "Records": [
                {
                    "messageId": "msg-fail",
                    "receiptHandle": "handle-1",
                    "body": json.dumps({"Type": "Notification", "Message": v2_message_raw}),
                    "eventSource": "aws:sqs",
                    "eventSourceARN": "arn:aws:sqs:eu-west-2:123456789012:test-queue",
                    "awsRegion": "eu-west-2",
                },
                {
                    "messageId": "msg-ok",
                    "receiptHandle": "handle-2",
                    "body": json.dumps({"Type": "Notification", "Message": v2_message_raw}),
                    "eventSource": "aws:sqs",
                    "eventSourceARN": "arn:aws:sqs:eu-west-2:123456789012:test-queue",
                    "awsRegion": "eu-west-2",
                },
            ],
        }

        result = lambda_function.handler(event=two_message_sqs_event, context=handler_context)

        assert result == {"batchItemFailures": [{"itemIdentifier": "msg-fail"}]}

    @patch("src.ds_caselaw_ingester.lambda_function.s3_client")
    @patch(
        "src.ds_caselaw_ingester.lambda_function.perform_ingest",
        side_effect=exceptions.FileNotFoundException("test-sns-still-works"),
    )
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest")
    @patch("src.ds_caselaw_ingester.lambda_function.rollbar.report_exc_info")
    @patch("src.ds_caselaw_ingester.lambda_function.api_client", autospec=True)
    def test_sns_handler_still_works(
        self,
        mock_api_client,
        mock_rollbar_call,
        mock_ingest,
        mock_perform_ingest,
        mock_s3_client,
        handler_context,
    ):
        """Direct SNS events still work (backward compatibility)."""
        message = v2_message_raw
        event = {"Records": [{"Sns": {"Message": message}}]}
        result = lambda_function.handler(event=event, context=handler_context)

        mock_rollbar_call.assert_called_with(level="error")
        # SNS records have no messageId, so no batch failures reported
        assert result == {"batchItemFailures": []}

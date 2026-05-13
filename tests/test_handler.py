import logging
from unittest.mock import ANY, PropertyMock, call, patch

import pytest
import rollbar
from caselawclient.factories import IdentifierResolutionsFactory
from caselawclient.models.identifiers.neutral_citation import NeutralCitationNumber
from caselawclient.types import DocumentURIString

from src.ds_caselaw_ingester import exceptions, lambda_function

from .conftest import error_message_raw, s3_message_raw, v2_message_raw
from .helpers import (
    assert_log_does_not_have_message_starting,
    assert_log_has_message,
    assert_log_has_message_starting,
    assert_log_shows_successful_ingest,
    create_fake_bulk_file,
    create_fake_error_file,
    create_fake_tdr_file,
)

rollbar.init(access_token=None, enabled=False)


class TestHandler:
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
    def test_handler_messages_v2_normal(
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
    ):
        mock_s3_client.download_file = create_fake_tdr_file
        doc = apiclient.get_document_by_uri.return_value
        doc.neutral_citation = None
        mock_doc.return_value = doc

        message = v2_message_raw
        event = {"Records": [{"Sns": {"Message": message}}, {"Sns": {"Message": message}}]}
        lambda_function.handler(event=event, context=None)

        assert_log_shows_successful_ingest(caplog)
        assert_log_does_not_have_message_starting(caplog, "publishing")
        assert "image1.png" in caplog.text
        notify_update.assert_called()
        assert notify_update.call_count == 2
        notify_new.assert_not_called()
        modify_filename.assert_not_called()
        doc.publish.assert_not_called()

        annotation.assert_called_with(
            ANY,
            automated=False,
            message="Updated document submitted by TDR user",
            payload=ANY,
        )
        assert annotation.call_count == 2
        doc.identifiers.add.assert_not_called()
        doc.identifiers.save.assert_not_called()

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
    def test_handler_messages_s3(
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
    ):
        """Test that, with appropriate stubs, an S3 message passes through the parsing process"""
        mock_s3_client.download_file = create_fake_bulk_file
        mock_uuid4.return_value = "a1b2-c3d4"
        doc = apiclient.get_document_by_uri.return_value
        doc.neutral_citation = "[2012] UKUT 82 (IAC)"
        mock_doc.return_value = doc

        message = s3_message_raw
        event = {"Records": [{"Sns": {"Message": message}}, {"Sns": {"Message": message}}]}
        lambda_function.handler(event=event, context=None)

        assert_log_shows_successful_ingest(caplog)

        assert_log_has_message(caplog, "Ingester Start: Consignment reference BULK-0")
        assert_log_has_message(caplog, "tar.gz saved locally as /tmp/BULK-0.tar.gz")
        assert_log_has_message_starting(caplog, "publishing")

        doc.publish.assert_called_with()
        notify_new.assert_not_called()
        notify_updated.assert_not_called()
        modify_filename.assert_not_called()

        annotation.assert_called_with(
            ANY,
            automated=True,
            message="Updated document uploaded by Find Case Law",
            payload=ANY,
        )
        assert annotation.call_count == 2
        assert doc.identifiers.add.call_args_list[0].args[0].value == "[2012] UKUT 82 (IAC)"
        assert type(doc.identifiers.add.call_args_list[0].args[0]) is NeutralCitationNumber
        doc.save_identifiers.assert_called()

    @patch("src.ds_caselaw_ingester.lambda_function.api_client", autospec=True)
    @patch("src.ds_caselaw_ingester.lambda_function.s3_client")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_updated_judgment_notification")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_new_judgment_notification")
    @patch("src.ds_caselaw_ingester.ingester.VersionAnnotation")
    @patch("src.ds_caselaw_ingester.ingester.modify_filename")
    @patch("src.ds_caselaw_ingester.ingester.Document")
    @patch(
        "src.ds_caselaw_ingester.lambda_function.Ingest.database_location",
        new_callable=PropertyMock,
        return_value=(DocumentURIString("uuid"), False),
    )
    def test_handler_messages_v2_parser_error(
        self,
        mock_determine_uri,
        mock_doc,
        modify_filename,
        annotation,
        notify_new,
        notify_update,
        mock_s3_client,
        apiclient,
        caplog: pytest.LogCaptureFixture,
    ):
        mock_s3_client.download_file = create_fake_error_file
        mock_doc.return_value = apiclient.get_document_by_uri.return_value

        message = error_message_raw

        event = {"Records": [{"Sns": {"Message": message}}, {"Sns": {"Message": message}}]}
        lambda_function.handler(event=event, context=None)

        assert_log_has_message(caplog, "tar.gz saved locally as /tmp/TDR-2025-CN7V.tar.gz")
        assert_log_has_message(
            caplog,
            "No XML file found in tarfile. consignment reference: TDR-2025-CN7V. Falling back to parser.log contents.",
            logging.WARNING,
        )
        assert_log_has_message(caplog, "Ingesting document uuid")
        assert_log_has_message(caplog, "Inserted judgment xml for uuid")
        assert_log_has_message(caplog, "extracted source filename is 'failures_TDR-2025-CN7V.docx'")
        assert_log_has_message(caplog, "Upload Successful uuid/TDR-2025-CN7V.tar.gz")
        assert_log_has_message(caplog, "saved tar.gz as '/tmp/TDR-2025-CN7V.tar.gz'")
        assert_log_has_message(caplog, "Upload Successful uuid/uuid.docx")
        assert_log_has_message(caplog, "Upload Successful uuid/parser.log")
        assert_log_has_message(caplog, "Ingestion complete")
        assert_log_does_not_have_message_starting(caplog, "publishing")
        notify_new.assert_called()
        assert notify_new.call_count == 2
        notify_update.assert_not_called()
        modify_filename.assert_not_called()
        mock_doc.publish.assert_not_called()

        annotation.assert_called_with(
            ANY,
            automated=False,
            message="New document uploaded by Find Case Law",
            payload=ANY,
        )
        assert annotation.call_count == 2
        mock_doc.identifiers.add.assert_not_called()
        mock_doc.identifiers.save.assert_not_called()

    @patch("src.ds_caselaw_ingester.lambda_function.s3_client")
    @patch(
        "src.ds_caselaw_ingester.lambda_function.perform_ingest",
        side_effect=[
            exceptions.FileNotFoundException("test"),
            exceptions.DocxFilenameNotFoundException("test2"),
            exceptions.CannotPublishException(),
        ],
    )
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest")
    @patch("src.ds_caselaw_ingester.lambda_function.rollbar.report_exc_info")
    @patch("src.ds_caselaw_ingester.lambda_function.api_client", autospec=True)
    def test_handler_exception_handled(
        self,
        mock_api_client,
        mock_rollbar_call,
        mock_ingest,
        mock_perform_ingest,
        mock_s3_client,
        caplog,
    ):
        message = s3_message_raw
        event = {
            "Records": [{"Sns": {"Message": message}}, {"Sns": {"Message": message}}, {"Sns": {"Message": message}}],
        }
        lambda_function.handler(event=event, context=None)

        # rollbar is called each time it fails
        mock_rollbar_call.assert_has_calls([call(level="error"), call(level="error"), call(level="error")])

        # stacktraces are in the log
        assert_log_has_message(caplog, "Error processing message", logging.ERROR)
        assert "Traceback (most recent call last):" in caplog.text
        assert "ds_caselaw_ingester.exceptions.FileNotFoundException: test" in caplog.text

        # the first invocation does not block the second
        assert "ds_caselaw_ingester.exceptions.DocxFilenameNotFoundException: test2" in caplog.text

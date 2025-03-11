import copy
import json
import os
import xml.etree.ElementTree as ET
from unittest.mock import ANY, MagicMock, PropertyMock, call, patch

import pytest
import rollbar
from callee import Contains
from caselawclient.Client import (
    MarklogicCommunicationError,
    MarklogicResourceNotFoundError,
)
from caselawclient.models.identifiers.neutral_citation import NeutralCitationNumber
from caselawclient.models.judgments import Judgment
from caselawclient.models.parser_logs import ParserLog
from caselawclient.models.press_summaries import PressSummary
from notifications_python_client.notifications import NotificationsAPIClient

from src.ds_caselaw_ingester import exceptions, ingester, lambda_function

from .conftest import error_message_raw, s3_message_raw, v2_message, v2_message_raw
from .helpers import create_fake_bulk_file, create_fake_error_file, create_fake_tdr_file

rollbar.init(access_token=None, enabled=False)


def assert_log_sensible(log):
    assert "Ingester Start: Consignment reference" in log
    assert "tar.gz saved locally as" in log
    assert "Ingesting document" in log
    assert "Updated judgment xml" in log
    assert "Upload Successful" in log
    assert "Ingestion complete" in log
    assert "Invalid XML file" not in log
    assert "No XML file found" not in log


class TestHandler:
    @patch("src.ds_caselaw_ingester.lambda_function.api_client", autospec=True)
    @patch("src.ds_caselaw_ingester.lambda_function.boto3.session.Session")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_updated_judgment_notification")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_new_judgment_notification")
    @patch("src.ds_caselaw_ingester.ingester.VersionAnnotation")
    @patch("src.ds_caselaw_ingester.ingester.modify_filename")
    def test_handler_messages_v2(
        self,
        modify_filename,
        annotation,
        notify_new,
        notify_update,
        boto_session,
        apiclient,
        capsys,
    ):
        boto_session.return_value.client.return_value.download_file = create_fake_tdr_file
        doc = apiclient.get_document_by_uri.return_value
        doc.neutral_citation = None

        message = v2_message_raw
        event = {"Records": [{"Sns": {"Message": message}}, {"Sns": {"Message": message}}]}
        lambda_function.handler(event=event, context=None)

        log = capsys.readouterr().out
        assert_log_sensible(log)
        assert "publishing" not in log
        assert "image1.png" in log
        notify_update.assert_called()
        assert notify_update.call_count == 2
        notify_new.assert_not_called()
        modify_filename.assert_not_called()

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
    @patch("src.ds_caselaw_ingester.lambda_function.boto3.session.Session")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_new_judgment_notification")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_updated_judgment_notification")
    @patch("src.ds_caselaw_ingester.ingester.VersionAnnotation")
    @patch("src.ds_caselaw_ingester.ingester.modify_filename")
    @patch("src.ds_caselaw_ingester.ingester.uuid4")
    def test_handler_messages_s3(
        self,
        mock_uuid4,
        modify_filename,
        annotation,
        notify_new,
        notify_updated,
        boto_session,
        apiclient,
        capsys,
    ):
        """Test that, with appropriate stubs, an S3 message passes through the parsing process"""
        boto_session.return_value.client.return_value.download_file = create_fake_bulk_file
        doc = apiclient.get_document_by_uri.return_value
        doc.neutral_citation = "[2012] UKUT 82 (IAC)"
        mock_uuid4.return_value = "a1b2-c3d4"

        message = s3_message_raw
        event = {"Records": [{"Sns": {"Message": message}}, {"Sns": {"Message": message}}]}
        lambda_function.handler(event=event, context=None)

        log = capsys.readouterr().out
        assert "Ingester Start: Consignment reference BULK-0" in log
        assert "tar.gz saved locally as /tmp/BULK-0.tar.gz" in log
        assert "Ingesting document" in log
        assert "Updated judgment xml" in log
        assert "Upload Successful" in log
        assert "Ingestion complete" in log
        assert "publishing" in log
        assert "Invalid XML file" not in log
        assert "No XML file found" not in log
        # apiclient.set_published.assert_called_with("d-a1b2-c3d4", True)
        apiclient.set_published.assert_called_with("ukut/iac/2012/82", True)
        assert apiclient.set_published.call_count == 2
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
    @patch("src.ds_caselaw_ingester.lambda_function.boto3.session.Session")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_updated_judgment_notification")
    @patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_new_judgment_notification")
    @patch("src.ds_caselaw_ingester.ingester.VersionAnnotation")
    @patch("src.ds_caselaw_ingester.ingester.modify_filename")
    def test_handler_messages_v2_parser_error(
        self,
        modify_filename,
        annotation,
        notify_new,
        notify_update,
        boto_session,
        apiclient,
        capsys,
    ):
        boto_session.return_value.client.return_value.download_file = create_fake_error_file
        doc = apiclient.get_document_by_uri.return_value
        doc.neutral_citation = None

        message = error_message_raw

        event = {"Records": [{"Sns": {"Message": message}}, {"Sns": {"Message": message}}]}
        lambda_function.handler(event=event, context=None)

        log = capsys.readouterr().out
        assert_log_sensible(log)
        assert "publishing" not in log
        assert "image1.png" in log
        notify_update.assert_called()
        assert notify_update.call_count == 2
        notify_new.assert_not_called()
        modify_filename.assert_not_called()

        annotation.assert_called_with(
            ANY,
            automated=False,
            message="Updated document submitted by TDR user",
            payload=ANY,
        )
        assert annotation.call_count == 2
        doc.identifiers.add.assert_not_called()
        doc.identifiers.save.assert_not_called()


class TestLambda:
    def test_store_metadata(self, v2_ingest):
        v2_ingest.metadata = {
            "parameters": {
                "TDR": {
                    "Source-Organization": "Ministry of Justice",
                    "Contact-Name": "Tom King",
                    "Internal-Sender-Identifier": "TDR-2021-CF6L",
                    "Consignment-Completed-Datetime": "2021-12-16T14:54:06Z",
                    "Contact-Email": "someone@example.com",
                },
            },
        }
        v2_ingest.uri = "uri"

        v2_ingest.api_client.set_property = MagicMock()
        v2_ingest.store_metadata()
        calls = [
            call("uri", name="source-organisation", value="Ministry of Justice"),
            call("uri", name="source-name", value="Tom King"),
            call("uri", name="source-email", value="someone@example.com"),
            call("uri", name="transfer-consignment-reference", value="TDR-2021-CF6L"),
            call("uri", name="transfer-received-at", value="2021-12-16T14:54:06Z"),
        ]
        v2_ingest.api_client.set_property.assert_has_calls(calls)

    @patch.dict(
        os.environ,
        {
            "NOTIFY_API_KEY": "ingester-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "EDITORIAL_UI_BASE_URL": "http://editor.url/",
            "NOTIFY_EDITORIAL_ADDRESS": "test@notifications.service.gov.uk",
            "NOTIFY_NEW_JUDGMENT_TEMPLATE_ID": "template-id",
            "ROLLBAR_ENV": "prod",
        },
        clear=True,
    )
    @patch("builtins.print")
    def test_send_new_judgment_notification(self, mock_print, v2_ingest):
        v2_ingest.uri = "d-4444"
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=d-4444",
            "consignment": "TDR-2021-CF6L",
            "submitter": "Tom King, Ministry of Justice <someone@example.com>",
            "submitted_at": "2021-12-16T14:54:06Z",
            "doctype": "judgment",
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_new_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )
        mock_print.assert_called_with(Contains("Sent new notification to test@notifications.service.gov.uk"))

    @patch.dict(
        os.environ,
        {
            "NOTIFY_API_KEY": "ingester-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "EDITORIAL_UI_BASE_URL": "http://editor.url/",
            "NOTIFY_EDITORIAL_ADDRESS": "test@notifications.service.gov.uk",
            "NOTIFY_NEW_JUDGMENT_TEMPLATE_ID": "template-id",
            "ROLLBAR_ENV": "prod",
        },
        clear=True,
    )
    @patch("builtins.print")
    def test_send_new_judgment_notification_with_no_tdr_section(self, mock_print, v2_ingest):
        v2_ingest.metadata = {}
        v2_ingest.uri = "d-444"
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=d-444",
            "consignment": "unknown",
            "submitter": "unknown, unknown <unknown>",
            "submitted_at": "unknown",
            "doctype": "judgment",
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_new_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )
        mock_print.assert_called_with(Contains("Sent new notification to test@notifications.service.gov.uk"))

    @patch.dict(
        os.environ,
        {"ROLLBAR_ENV": "staging"},
        clear=True,
    )
    @patch("builtins.print")
    def test_do_not_send_new_judgment_notification_on_staging(self, mock_print, v2_ingest):
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_new_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_not_called()

    @patch.dict(
        os.environ,
        {
            "NOTIFY_API_KEY": "ingester-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "EDITORIAL_UI_BASE_URL": "http://editor.url/",
            "NOTIFY_EDITORIAL_ADDRESS": "test@notifications.service.gov.uk",
            "NOTIFY_UPDATED_JUDGMENT_TEMPLATE_ID": "template-id",
            "ROLLBAR_ENV": "prod",
        },
        clear=True,
    )
    @patch("builtins.print")
    def test_send_updated_judgment_notification(self, mock_print, v2_ingest):
        v2_ingest.uri = "uri"
        v2_ingest.metadata = {
            "parameters": {
                "TDR": {
                    "Source-Organization": "Ministry of Justice",
                    "Contact-Name": "Tom King",
                    "Internal-Sender-Identifier": "TDR-2021-CF6L",
                    "Consignment-Completed-Datetime": "2021-12-16T14:54:06Z",
                    "Contact-Email": "someone@example.com",
                },
            },
        }
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=uri",
            "consignment": "TDR-2021-CF6L",
            "submitter": "Tom King, Ministry of Justice <someone@example.com>",
            "submitted_at": "2021-12-16T14:54:06Z",
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_updated_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )
        mock_print.assert_called_with(Contains("Sent update notification to test@notifications.service.gov.uk"))

    @patch.dict(
        os.environ,
        {
            "NOTIFY_API_KEY": "ingester-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "EDITORIAL_UI_BASE_URL": "http://editor.url/",
            "NOTIFY_EDITORIAL_ADDRESS": "test@notifications.service.gov.uk",
            "NOTIFY_UPDATED_JUDGMENT_TEMPLATE_ID": "template-id",
            "ROLLBAR_ENV": "prod",
        },
        clear=True,
    )
    @patch("builtins.print")
    def test_send_updated_judgment_notification_with_no_tdr_section(self, mock_print, v2_ingest):
        v2_ingest.metadata = {}
        v2_ingest.uri = "uri"
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=uri",
            "consignment": "unknown",
            "submitter": "unknown, unknown <unknown>",
            "submitted_at": "unknown",
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_updated_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )
        mock_print.assert_called_with(Contains("Sent update notification to test@notifications.service.gov.uk"))

    @patch("src.ds_caselaw_ingester.ingester.AWS_BUCKET_NAME", "private-bucket")
    def test_update_published_documents(self, v2_ingest):
        contents = {"Contents": [{"Key": "file1.ext"}, {"Key": "file2.ext"}]}

        v2_ingest.s3_client.list_objects = MagicMock(return_value=contents)
        v2_ingest.s3_client.copy = MagicMock()

        calls = [
            call(
                {"Bucket": "private-bucket", "Key": "file1.ext"},
                "public-bucket",
                "file1.ext",
                {},
            ),
            call(
                {"Bucket": "private-bucket", "Key": "file2.ext"},
                "public-bucket",
                "file2.ext",
                {},
            ),
        ]
        v2_ingest.update_published_documents("public-bucket")
        v2_ingest.s3_client.copy.assert_has_calls(calls)

    def test_get_consignment_reference_success_v2(self):
        message = copy.deepcopy(v2_message)
        message["parameters"]["reference"] = "THIS_REF"
        result = lambda_function.get_consignment_reference(message)
        assert result == "THIS_REF"

    def test_get_consignment_reference_empty_v2(self):
        message = copy.deepcopy(v2_message)
        message["parameters"]["reference"] = ""
        message["parameters"]["bundleFileURI"] = "http://172.17.0.2:4566/te-editorial-out-int/ewca_civ_2021_1881.tar.gz"
        with pytest.raises(exceptions.InvalidMessageException):
            lambda_function.get_consignment_reference(message)

    def test_get_consignment_reference_missing_v2(self):
        message = copy.deepcopy(v2_message)
        del message["parameters"]["reference"]
        message["parameters"]["bundleFileURI"] = "http://172.17.0.2:4566/te-editorial-out-int/ewca_civ_2021_1881.tar.gz"
        with pytest.raises(exceptions.InvalidMessageException):
            lambda_function.get_consignment_reference(message)

    def test_get_consignment_reference_presigned_url_v2(self):
        message = copy.deepcopy(v2_message)
        message["parameters"]["reference"] = ""
        message["parameters"]["bundleFileURI"] = (
            "http://172.17.0.2:4566/te-editorial-out-int/ewca_civ_2021_1881.tar.gz?randomstuffafterthefilename"
        )
        with pytest.raises(exceptions.InvalidMessageException):
            lambda_function.get_consignment_reference(message)

    def test_malformed_message(self):
        message = {"something-unexpected": "???"}
        with pytest.raises(exceptions.InvalidMessageException):
            lambda_function.get_consignment_reference(message)

    def test_update_document_xml_success(self, v2_ingest):
        v2_ingest.api_client.get_judgment_xml = MagicMock(return_value=True)
        v2_ingest.api_client.update_document_xml = MagicMock(return_value=True)
        assert v2_ingest.update_document_xml() is True

    def test_update_document_xml_success_no_tdr(self, v2_ingest):
        v2_ingest.api_client.get_judgment_xml = MagicMock(return_value=True)
        v2_ingest.api_client.update_document_xml = MagicMock(return_value=True)
        v2_ingest.metadata = {"parameters": {}}
        result = v2_ingest.update_document_xml()
        assert result is True

    def test_update_document_xml_judgment_does_not_exist(self, v2_ingest):
        v2_ingest.api_client.get_judgment_xml = MagicMock(side_effect=MarklogicResourceNotFoundError("error"))
        v2_ingest.api_client.update_document_xml = MagicMock(return_value=True)
        result = v2_ingest.update_document_xml()
        assert result is False

    def test_update_document_xml_judgment_does_not_save(self, v2_ingest):
        v2_ingest.api_client.get_judgment_xml = MagicMock(return_value=True)
        v2_ingest.api_client.update_document_xml = MagicMock(side_effect=MarklogicCommunicationError("error"))
        with pytest.raises(MarklogicCommunicationError):
            v2_ingest.update_document_xml()

    def test_insert_document_xml_success_judgment(self, v2_ingest):
        xml = ET.XML(
            "<akomaNtoso xmlns='http://docs.oasis-open.org/legaldocml/ns/akn/3.0'><judgment><xml>Here's some xml</xml></judgment></akomaNtoso>",
        )
        v2_ingest.api_client.insert_document_xml = MagicMock(return_value=True)
        v2_ingest.uri = "a/fake/uri"
        v2_ingest.xml = xml
        result = v2_ingest.insert_document_xml()
        assert result is True
        v2_ingest.api_client.insert_document_xml.assert_called_once_with(
            document_uri=v2_ingest.uri,
            document_xml=xml,
            annotation=ANY,
            document_type=Judgment,
        )

    def test_insert_document_xml_success_press_summary(self, v2_ingest):
        xml = ET.XML(
            "<akomaNtoso xmlns='http://docs.oasis-open.org/legaldocml/ns/akn/3.0'><doc name='pressSummary'><xml>Here's some xml</xml></doc></akomaNtoso>",
        )
        v2_ingest.api_client.insert_document_xml = MagicMock(return_value=True)
        v2_ingest.uri = "a/fake/uri"
        v2_ingest.xml = xml
        result = v2_ingest.insert_document_xml()
        assert result is True
        v2_ingest.api_client.insert_document_xml.assert_called_once_with(
            document_uri=v2_ingest.uri,
            document_xml=xml,
            annotation=ANY,
            document_type=PressSummary,
        )

    def test_insert_document_xml_parser_error(self, v2_ingest):
        """Parser errors are successfully imported with document type Error"""
        xml = ET.XML(
            "<error/>",
        )
        v2_ingest.api_client.insert_document_xml = MagicMock(return_value=True)
        v2_ingest.uri = "a/fake/uri"
        v2_ingest.xml = xml
        result = v2_ingest.insert_document_xml()
        assert result is True
        v2_ingest.api_client.insert_document_xml.assert_called_once_with(
            document_uri=v2_ingest.uri,
            document_xml=xml,
            annotation=ANY,
            document_type=ParserLog,
        )

    def test_insert_document_xml_failure(self, v2_ingest):
        v2_ingest.api_client.insert_document_xml = MagicMock(side_effect=MarklogicCommunicationError("error"))
        with pytest.raises(MarklogicCommunicationError):
            v2_ingest.insert_document_xml()

    @patch(
        "src.ds_caselaw_ingester.lambda_function.Ingest.save_tar_file_in_s3",
        return_value="/tmp/TDR-2022-DNWR.tar.gz",
    )
    @patch("caselawclient.models.documents.Document")
    def test_unpublish_updated_judgment(self, MockDocument, fake_s3):
        # Mock the Document class
        # mock_document_instance = MagicMock()
        # MockDocument.side_effect = lambda _uri, _api_client: mock_document_instance

        mock_document_instance = MockDocument.return_value
        mock_document_instance.unpublish = MagicMock()

        uri = "a/fake/uri"

        # Create a mock message object
        mock_message = MagicMock()
        mock_message.get_consignment_reference.return_value = "test-consignment-reference"
        mock_message.message = "Test message"
        mock_message.originator = "TDR"

        # Create an instance of the Ingest class
        ingest = ingester.Ingest(
            message=mock_message,
            destination_bucket="test-destination-bucket",
            api_client=MagicMock(),
            s3_client=MagicMock(),
        )

        ingest.uri = uri

        ingest.unpublish_updated_judgment()

        MockDocument.assert_called_once_with(uri, ingest.api_client)
        mock_document_instance.unpublish.assert_called_once()

    @patch(
        "src.ds_caselaw_ingester.lambda_function.Ingest.save_tar_file_in_s3",
        return_value="/tmp/TDR-2022-DNWR.tar.gz",
    )
    @patch("caselawclient.models.documents.Document")
    def test_publish(self, MockDocument, fake_s3):
        # Mock the Document class
        # mock_document_instance = MagicMock()
        # MockDocument.side_effect = lambda _uri, _api_client: mock_document_instance

        mock_document_instance = MockDocument.return_value
        mock_document_instance.unpublish = MagicMock()

        uri = "a/fake/uri"

        # Create a mock message object
        mock_message = MagicMock()
        mock_message.get_consignment_reference.return_value = "test-consignment-reference"
        mock_message.message = "Test message"
        mock_message.originator = "TDR"

        # Create an instance of the Ingest class
        ingest = ingester.Ingest(
            message=mock_message,
            destination_bucket="test-destination-bucket",
            api_client=MagicMock(),
            s3_client=MagicMock(),
        )

        ingest.uri = uri

        ingest.publish()

        MockDocument.assert_called_once_with(uri, ingest.api_client)
        mock_document_instance.publish.assert_called_once()

    def test_user_agent(self):
        assert "ingester" in lambda_function.api_client.session.headers["User-Agent"]

    @patch("os.path.exists", return_value=True)
    @patch("os.getenv", return_value="")
    def test_unquote_s3(self, getenv, os):
        my_raw = s3_message_raw.replace(
            "QX/e31b117f-ff09-49b6-a697-7952c7a67384/BULK-0.tar.gz",
            "2010+Reported/%5B2010%5D/1.tar.gz",
        )
        assert "2010+Reported" in my_raw

        decoder = json.decoder.JSONDecoder()
        message = lambda_function.Message.from_message(decoder.decode(my_raw))
        mock_s3_client = MagicMock()
        message.save_s3_response(mock_s3_client)
        mock_s3_client.download_file.assert_called_with(ANY, "2010 Reported/[2010]/1.tar.gz", ANY)


modify_filename_data = [
    ["TRE-2023-XYZ.tar.gz", "TRE-2023-XYZ_.tar.gz"],
    ["/a/b/c.d.e", "/a/b/c_.d.e"],
    [
        "",
        "_",
    ],
]


@pytest.mark.parametrize("was, now", modify_filename_data)
def test_modify_targz_filename(was, now):
    assert ingester.modify_filename(was, addition="_") == now


class TestPublicationLogic:
    def test_v2_ingest_publish(self, v2_ingest):
        assert v2_ingest.will_publish() is False

    def test_s3_ingest_publish(self, s3_ingest):
        assert s3_ingest.will_publish() is True

    def test_s3_ingest_publish_no_force_publish(self, s3_ingest):
        with patch("src.ds_caselaw_ingester.ingester.Metadata.force_publish", new_callable=PropertyMock) as mock:
            mock.return_value = False
            assert s3_ingest.will_publish() is False

    def test_fcl_not_published_if_not_published(self, fcl_ingest):
        fcl_ingest.api_client.get_published.return_value = False
        assert fcl_ingest.will_publish() is False

    def test_fcl_published_if_published(self, fcl_ingest):
        fcl_ingest.api_client.get_published.return_value = True
        assert fcl_ingest.will_publish() is True


@patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_updated_judgment_notification")
@patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_new_judgment_notification")
@patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_bulk_judgment_notification")
class TestEmailLogic:
    def test_v2_ingest_publish_email_update(self, bulk, new, updated, v2_ingest):
        v2_ingest.inserted = False
        v2_ingest.updated = True

        v2_ingest.send_email()

        updated.assert_called()
        new.assert_not_called()
        bulk.assert_not_called()

    def test_v2_ingest_publish_email_insert(self, bulk, new, updated, v2_ingest):
        v2_ingest.inserted = True
        v2_ingest.updated = False

        v2_ingest.send_email()

        updated.assert_not_called()
        new.assert_called()
        bulk.assert_not_called()

    def test_fcl_ingest_no_email(self, bulk, new, updated, fcl_ingest):
        fcl_ingest.inserted = True
        fcl_ingest.updated = False
        fcl_ingest.send_email()

        updated.assert_not_called()
        new.assert_not_called()
        bulk.assert_not_called()

    @patch("src.ds_caselaw_ingester.ingester.Metadata.force_publish", new_callable=PropertyMock)
    def test_s3_ingest_no_email_if_publish(self, mock_property, bulk, new, updated, s3_ingest):
        mock_property.return_value = True
        s3_ingest.send_email()

        updated.assert_not_called()
        new.assert_not_called()
        bulk.assert_not_called()

    @patch("src.ds_caselaw_ingester.ingester.Metadata.force_publish", new_callable=PropertyMock)
    def test_s3_ingest_email_if_not_publish(self, mock_property, bulk, new, updated, s3_ingest):
        mock_property.return_value = False
        s3_ingest.send_email()

        updated.assert_not_called()
        new.assert_not_called()

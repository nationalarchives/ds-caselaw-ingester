import copy
import json
import os
import xml.etree.ElementTree as ET
from unittest.mock import ANY, MagicMock, call, patch

import pytest
import rollbar
from callee import Contains
from caselawclient.Client import (
    MarklogicCommunicationError,
    MarklogicResourceNotFoundError,
)
from caselawclient.models.documents import Document
from caselawclient.models.judgments import Judgment
from caselawclient.models.press_summaries import PressSummary
from notifications_python_client.notifications import NotificationsAPIClient

from src.ds_caselaw_ingester import exceptions, ingester, lambda_function

from .conftest import s3_message_raw, v2_message

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
        v2_ingest.uri = "ewca/2023/1/press-summary/1"
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=ewca/2023/1/press-summary/1",
            "consignment": "TDR-2021-CF6L",
            "submitter": "Tom King, Ministry of Justice <someone@example.com>",
            "submitted_at": "2021-12-16T14:54:06Z",
            "doctype": "Press Summary",
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
        v2_ingest.uri = "ewca/2023/1/press-summary/1"
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=ewca/2023/1/press-summary/1",
            "consignment": "unknown",
            "submitter": "unknown, unknown <unknown>",
            "submitted_at": "unknown",
            "doctype": "Press Summary",
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
            document_type=Document,
        )

    def test_insert_document_xml_failure(self, v2_ingest):
        v2_ingest.api_client.insert_document_xml = MagicMock(side_effect=MarklogicCommunicationError("error"))
        with pytest.raises(MarklogicCommunicationError):
            v2_ingest.insert_document_xml()

    def test_unpublish_updated_judgment(self, v2_ingest):
        uri = "a/fake/uri"
        v2_ingest.api_client.set_published = MagicMock()
        v2_ingest.uri = uri
        v2_ingest.unpublish_updated_judgment()
        v2_ingest.api_client.set_published.assert_called_with(uri, False)

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

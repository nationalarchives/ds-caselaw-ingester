import copy
import json
import os
from unittest.mock import ANY, MagicMock, PropertyMock, call, patch

import lxml.etree as ET
import pytest
import rollbar
from caselawclient.Client import (
    MarklogicCommunicationError,
)
from caselawclient.factories import IdentifierResolutionFactory, IdentifierResolutionsFactory
from caselawclient.models.judgments import Judgment
from caselawclient.models.parser_logs import ParserLog
from caselawclient.models.press_summaries import PressSummary
from caselawclient.types import DocumentURIString
from notifications_python_client.notifications import NotificationsAPIClient

from src.ds_caselaw_ingester import exceptions, ingester, lambda_function

from .conftest import s3_message_raw, v2_message
from .helpers import (
    assert_log_has_message_starting,
)

rollbar.init(access_token=None, enabled=False)

NULL_UPDATE_METADATA = '{\n  "Judgment-Update": null,\n  "Judgment-Update-Type": null,\n  "Judgment-Update-Details": null,\n  "Judgment-Neutral-Citation": null,\n  "Judgment-No-Neutral-Citation": null,\n  "Judgment-Reference": null\n}'


class TestLambda:
    def test_store_tdr_metadata(self, v2_ingest):
        v2_ingest.uri = "uri"
        v2_ingest.api_client.set_property = MagicMock()

        v2_ingest.store_tdr_metadata(
            {
                "Source-Organization": "Ministry of Justice",
                "Contact-Name": "Tom King",
                "Internal-Sender-Identifier": "TDR-2021-CF6L",
                "Consignment-Completed-Datetime": "2021-12-16T14:54:06Z",
                "Contact-Email": "someone@example.com",
                "Judgment-Neutral-Citation": "[2019] UKSC 1701",
            },
        )

        v2_ingest.api_client.set_property.assert_has_calls(
            [
                call("uri", name="source-organisation", value="Ministry of Justice"),
                call("uri", name="source-name", value="Tom King"),
                call("uri", name="source-email", value="someone@example.com"),
                call("uri", name="transfer-consignment-reference", value="TDR-2021-CF6L"),
                call("uri", name="transfer-received-at", value="2021-12-16T14:54:06Z"),
            ],
        )

    def test_store_parser_metadata(self, v2_ingest):
        v2_ingest.uri = "uri"
        v2_ingest.api_client.set_property = MagicMock()

        v2_ingest.store_parser_metadata({"parser_run_id": "607e7ef1-3b5e-431b-b115-bb1811767f5c"})

        v2_ingest.api_client.set_property.assert_has_calls(
            [
                call("uri", name="parser-run-id", value="607e7ef1-3b5e-431b-b115-bb1811767f5c"),
            ],
        )

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
    def test_send_new_judgment_notification(self, v2_ingest, caplog: pytest.LogCaptureFixture):
        v2_ingest.uri = "d-4444"
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=d-4444",
            "consignment": "TDR-2021-CF6L",
            "submitter": "Tom King, Ministry of Justice <someone@example.com>",
            "submitted_at": "2021-12-16T14:54:06Z",
            "doctype": "judgment",
            "update_metadata": NULL_UPDATE_METADATA,
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_new_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )

        assert_log_has_message_starting(caplog, "Sent new notification to test@notifications.service.gov.uk")

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
    def test_send_new_judgment_notification_with_no_tdr_section(self, v2_ingest, caplog: pytest.LogCaptureFixture):
        v2_ingest.metadata = {}
        v2_ingest.uri = "d-444"
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=d-444",
            "consignment": "unknown",
            "submitter": "unknown, unknown <unknown>",
            "submitted_at": "unknown",
            "doctype": "judgment",
            "update_metadata": NULL_UPDATE_METADATA,
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_new_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )
        assert_log_has_message_starting(caplog, "Sent new notification to test@notifications.service.gov.uk")

    @patch.dict(
        os.environ,
        {"ROLLBAR_ENV": "staging"},
        clear=True,
    )
    def test_do_not_send_new_judgment_notification_on_staging(self, v2_ingest):
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
    def test_send_updated_judgment_notification(self, v2_ingest, caplog: pytest.LogCaptureFixture):
        v2_ingest.uri = "uri"
        v2_ingest.metadata = {
            "parameters": {
                "TDR": {
                    "Source-Organization": "Ministry of Justice",
                    "Contact-Name": "Tom King",
                    "Internal-Sender-Identifier": "TDR-2021-CF6L",
                    "Consignment-Completed-Datetime": "2021-12-16T14:54:06Z",
                    "Contact-Email": "someone@example.com",
                    "Judgment-Update": True,
                    "Judgment-Update-Type": "judgment",
                    "Judgment-Update-Details": "details",
                    "Judgment-Neutral-Citation": "[2019] UKSC 1701",
                    "Judgment-No-Neutral-Citation": False,
                    "Judgment-Reference": "Case 1",
                },
            },
        }
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=uri",
            "consignment": "TDR-2021-CF6L",
            "submitter": "Tom King, Ministry of Justice <someone@example.com>",
            "submitted_at": "2021-12-16T14:54:06Z",
            "update_metadata": '{\n  "Judgment-Update": true,\n  "Judgment-Update-Type": "judgment",\n  "Judgment-Update-Details": "details",\n  "Judgment-Neutral-Citation": "[2019] UKSC 1701",\n  "Judgment-No-Neutral-Citation": false,\n  "Judgment-Reference": "Case 1"\n}',
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_updated_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )

        assert_log_has_message_starting(caplog, "Sent update notification to test@notifications.service.gov.uk")

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
    def test_send_updated_judgment_notification_with_no_tdr_section(self, v2_ingest, caplog: pytest.LogCaptureFixture):
        v2_ingest.metadata = {}
        v2_ingest.uri = "uri"
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=uri",
            "consignment": "unknown",
            "submitter": "unknown, unknown <unknown>",
            "submitted_at": "unknown",
            "update_metadata": NULL_UPDATE_METADATA,
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_updated_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )

        assert_log_has_message_starting(caplog, "Sent update notification to test@notifications.service.gov.uk")

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
        v2_ingest.update_document_xml()

    def test_update_document_xml_success_no_tdr(self, v2_ingest):
        v2_ingest.api_client.get_judgment_xml = MagicMock(return_value=True)
        v2_ingest.api_client.update_document_xml = MagicMock(return_value=True)
        v2_ingest.metadata = {"parameters": {}}
        v2_ingest.update_document_xml()

    def test_insert_document_xml_success_judgment(self, v2_ingest):
        xml = ET.XML(
            "<akomaNtoso xmlns='http://docs.oasis-open.org/legaldocml/ns/akn/3.0'><judgment><xml>Here's some xml</xml></judgment></akomaNtoso>",
        )
        v2_ingest.api_client.insert_document_xml = MagicMock(return_value=True)
        v2_ingest.uri = "a/fake/uri"
        v2_ingest.xml = xml
        v2_ingest.insert_document_xml()
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
        v2_ingest.insert_document_xml()
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
        v2_ingest.insert_document_xml()
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

    @patch("src.ds_caselaw_ingester.ingester.copy_file")
    @patch("src.ds_caselaw_ingester.ingester.extract_source_filename", return_value="file.pdf")
    def test_extension_is_retained_pdf(self, pdf_filename, copy_file, v2_ingest):
        v2_ingest.save_files_to_s3()
        (call,) = [x for x in copy_file.call_args_list if x.args[1] == "TDR-2022-DNWR/file.pdf"]
        assert call.args[3] == "v2-a1b2-c3d4.pdf"

    @patch("src.ds_caselaw_ingester.ingester.copy_file")
    @patch("src.ds_caselaw_ingester.ingester.extract_source_filename", return_value="file.docx")
    def test_extension_is_retained_docx(self, docx_filename, copy_file, v2_ingest):

        v2_ingest.save_files_to_s3()
        (call,) = [x for x in copy_file.call_args_list if x.args[1] == "TDR-2022-DNWR/file.docx"]
        assert call.args[3] == "v2-a1b2-c3d4.docx"

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

    @patch("src.ds_caselaw_ingester.ingester.Ingest.find_existing_document_by_ncn", return_value=None)
    def test_fcl_not_published_if_doesnt_exist(self, existing_uri, fcl_ingest):
        fcl_ingest.api_client.get_published.return_value = False
        assert fcl_ingest.will_publish() is False

    @patch("src.ds_caselaw_ingester.ingester.Ingest.find_existing_document_by_ncn", return_value="cat")
    def test_fcl_not_published_if_exists_but_not_published(self, existing_uri, fcl_ingest):
        fcl_ingest.api_client.get_published.return_value = False
        assert fcl_ingest.will_publish() is False

    @patch("src.ds_caselaw_ingester.ingester.Ingest.find_existing_document_by_ncn", return_value="cat")
    def test_fcl_published_if_published(self, existing_uri, fcl_ingest):
        fcl_ingest.api_client.get_published.return_value = True
        assert fcl_ingest.will_publish() is True


@patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_updated_judgment_notification")
@patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_new_judgment_notification")
@patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_bulk_judgment_notification")
class TestEmailLogic:
    def test_v2_ingest_publish_email_update(self, bulk, new, updated, v2_ingest):
        v2_ingest.exists_in_database = True

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


class TestIngesterExistingDocumentUriMethod:
    def test_no_resolutions(self, fcl_ingest):
        fcl_ingest.api_client.resolve_from_identifier_value.return_value = IdentifierResolutionsFactory.build([])
        assert fcl_ingest.find_existing_document_by_ncn is None

    def test_no_resolution_is_an_ncn(self, fcl_ingest):
        fcl_ingest.api_client.resolve_from_identifier_value.return_value = IdentifierResolutionsFactory.build(
            [IdentifierResolutionFactory.build(namespace="fclid")],
        )
        assert fcl_ingest.find_existing_document_by_ncn is None

    def test_one_resolution(self, v2_ingest):
        v2_ingest.api_client.resolve_from_identifier_value.return_value = IdentifierResolutionsFactory.build()
        assert v2_ingest.find_existing_document_by_ncn == "ewca/civ/2003/547"

    def test_many_resolutions(self, v2_ingest):
        v2_ingest.api_client.resolve_from_identifier_value.return_value = IdentifierResolutionsFactory.build(
            [IdentifierResolutionFactory.build(), IdentifierResolutionFactory.build()],
        )
        with pytest.raises(ingester.MultipleResolutionsFoundError):
            _ = v2_ingest.find_existing_document_by_ncn


class TestDatabaseLocation:
    """The ynn annotations on the test names refer to this version of the flowchart:
    https://github.com/nationalarchives/ds-caselaw-ingester/pull/311/files?short_path=81f315b#diff-81f315ba06f2786cef4c0a1d091d65b650897a6296ae371952d8475cef5d8b5e
    """

    @patch("src.ds_caselaw_ingester.ingester.uuid4", return_value="a1b2c3")
    def test_nn_no_parser_uri_or_ncn(self, uuid, v2_ingest):
        v2_ingest.api_client.resolve_from_identifier_value.return_value = []
        v2_ingest.api_client.resolve_from_identifier_slug.return_value = []
        v2_ingest.metadata_object.trimmed_uri.return_value = ""
        v2_ingest.extracted_ncn = None
        uri, exists = v2_ingest.database_location
        assert isinstance(uri, DocumentURIString)
        assert str(uri) == "d-a1b2c3"
        assert exists is False

    @patch("src.ds_caselaw_ingester.ingester.Metadata.trimmed_uri", new_callable=PropertyMock, return_value="uri")
    def test_yy_parser_uri_and_doc_in_marklogic(self, trimmed, v2_ingest):
        v2_ingest.api_client.resolve_from_identifier_slug.return_value = [
            IdentifierResolutionFactory.build(document_uri="/d-a1b2c3.xml", identifier_slug="ewca/civ/2003/547"),
        ]
        uri, exists = v2_ingest.database_location
        assert str(uri) == "d-a1b2c3"
        assert exists is True

    @patch("src.ds_caselaw_ingester.ingester.Metadata.trimmed_uri", new_callable=PropertyMock, return_value="uri")
    @patch("src.ds_caselaw_ingester.ingester.uuid4", return_value="a1b2c3")
    def test_ynyn_neither_uri_or_ncn_in_marklogic(self, uuid, trimmed_uri, v2_ingest):
        v2_ingest.api_client.resolve_from_identifier_slug.return_value = []
        v2_ingest.api_client.resolve_from_identifier_value.return_value = []
        # An NCN of [2022] EWCA Civ 111 is already present
        uri, exists = v2_ingest.database_location
        v2_ingest.api_client.resolve_from_identifier_slug.assert_called()
        v2_ingest.api_client.resolve_from_identifier_value.assert_called()
        assert str(uri) == "d-a1b2c3"
        assert exists is False

    @patch("src.ds_caselaw_ingester.ingester.Metadata.trimmed_uri", new_callable=PropertyMock, return_value="uri")
    @patch("src.ds_caselaw_ingester.ingester.uuid4", return_value="a1b2c3")
    def test_ynyy_ncn_in_marklogic(self, uuid, trimmed_uri, v2_ingest):
        v2_ingest.api_client.resolve_from_identifier_slug.return_value = []
        v2_ingest.api_client.resolve_from_identifier_value.return_value = [
            IdentifierResolutionFactory.build(document_uri="/uksc/2030/999.xml"),
        ]
        # An NCN of [2022] EWCA Civ 111 is already present
        uri, exists = v2_ingest.database_location
        v2_ingest.api_client.resolve_from_identifier_slug.assert_called()
        v2_ingest.api_client.resolve_from_identifier_value.assert_called()
        assert str(uri) == "uksc/2030/999"
        assert exists is True

    @patch("src.ds_caselaw_ingester.ingester.Metadata.trimmed_uri", new_callable=PropertyMock, return_value="uri")
    @patch("src.ds_caselaw_ingester.ingester.uuid4", return_value="a1b2c3")
    def test_ynn_uri_but_not_in_marklogic_no_ncn(self, uuid, trimmed_uri, v2_ingest):
        v2_ingest.api_client.resolve_from_identifier_slug.return_value = []
        v2_ingest.api_client.resolve_from_identifier_value.return_value = []
        v2_ingest.extracted_ncn = None
        v2_ingest.api_client.resolve_from_identifier_slug.assert_not_called()
        v2_ingest.api_client.resolve_from_identifier_value.assert_not_called()

        uri, exists = v2_ingest.database_location
        assert str(uri) == "d-a1b2c3"
        assert exists is False

    @patch("src.ds_caselaw_ingester.ingester.Metadata.trimmed_uri", new_callable=PropertyMock, return_value="")
    def test_nyy_no_parser_uri_but_ncn_metdata_and_existing_doc(self, trimmed_uri, v2_ingest):
        v2_ingest.api_client.resolve_from_identifier_slug.return_value = []
        v2_ingest.api_client.resolve_from_identifier_value.return_value = [
            IdentifierResolutionFactory.build(document_uri="/uksc/2030/999.xml"),
        ]
        v2_ingest.extracted_ncn = "[2030] UKSC 999"
        # v2_ingest.api_client.resolve_from_identifier_slug.assert_called()

        uri, exists = v2_ingest.database_location
        v2_ingest.api_client.resolve_from_identifier_value.assert_called_with("[2030] UKSC 999", published_only=False)
        assert str(uri) == "uksc/2030/999"
        assert exists is True

    @patch("src.ds_caselaw_ingester.ingester.Metadata.trimmed_uri", new_callable=PropertyMock, return_value="")
    @patch("src.ds_caselaw_ingester.ingester.uuid4", return_value="a1b2c3")
    def test_nyn_no_parser_uri_or_existing_doc_but_ncn_metdata(self, fake_uuid, trimmed_uri, v2_ingest):
        v2_ingest.api_client.resolve_from_identifier_value.return_value = []
        v2_ingest.extracted_ncn = "[2030] UKSC 999"

        uri, exists = v2_ingest.database_location
        v2_ingest.api_client.resolve_from_identifier_value.assert_called()
        assert str(uri) == "d-a1b2c3"
        assert exists is False

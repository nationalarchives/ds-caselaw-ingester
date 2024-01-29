import json
import os
import shutil
import tarfile
import xml.etree.ElementTree as ET
from unittest.mock import ANY, MagicMock, call, patch

import boto3
import lambda_function
import pytest
from botocore.exceptions import NoCredentialsError
from callee import Contains
from caselawclient.Client import (
    MarklogicCommunicationError,
    MarklogicResourceNotFoundError,
)
from notifications_python_client.notifications import NotificationsAPIClient

TDR_TARBALL_PATH = os.path.join(
    os.path.dirname(__file__),
    "../aws_examples/s3/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
)

BULK_TARBALL_PATH = os.path.join(
    os.path.dirname(__file__), "../aws_examples/s3/te-editorial-out-int/test3.tar.gz"
)


v2_message_raw = """
    {
        "properties": {
            "messageType":
                "uk.gov.nationalarchives.tre.messages.judgmentpackage.available.JudgmentPackageAvailable",
            "timestamp": "2023-05-15T09:14:53.791409Z",
            "function": "staging-tre-judgment-packer-lambda",
            "producer": "TRE",
            "executionId": "cc46e39f-76ef-43c9-a6d7-c6b064c3556a",
            "parentExecutionId": "d26458ae-19a7-4159-8381-805075163198"
        },
        "parameters": {
            "status": "JUDGMENT_PARSE_NO_ERRORS",
            "reference": "TDR-2022-DNWR",
            "originator": "FCL",
            "bundleFileURI": "http://172.17.0.2:4566/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
            "metadataFilePath": "/metadata.json",
            "metadataFileType": "Json"
        }
    }
    """

s3_message = {
    "Records": [
        {
            "eventSource": "aws:s3",
            "s3": {
                "bucket": {
                    "name": "staging-tre-court-document-pack-out",
                },
                "object": {
                    "key": "QX/e31b117f-ff09-49b6-a697-7952c7a67384/BULK-0.tar.gz",
                },
            },
        }
    ]
}
v2_message = json.loads(v2_message_raw)
s3_message_raw = json.dumps(s3_message)


def create_fake_tdr_file(*args, **kwargs):
    shutil.copyfile(TDR_TARBALL_PATH, "/tmp/TDR-2022-DNWR.tar.gz")


def create_fake_bulk_file(*args, **kwargs):
    shutil.copyfile(BULK_TARBALL_PATH, "/tmp/BULK-0.tar.gz")


class TestHandler:
    @patch("lambda_function.api_client", autospec=True)
    @patch("lambda_function.boto3.session.Session")
    @patch("lambda_function.send_updated_judgment_notification")
    @patch("lambda_function.send_new_judgment_notification")
    @patch("lambda_function.VersionAnnotation")
    def test_handler_messages_v2(
        self,
        annotation,
        notify_new,
        notify_update,
        boto_session,
        apiclient,
        capsys,
    ):
        boto_session.return_value.client.return_value.download_file = (
            create_fake_tdr_file
        )

        message = v2_message_raw
        event = {
            "Records": [{"Sns": {"Message": message}}, {"Sns": {"Message": message}}]
        }
        lambda_function.handler(event=event, context=None)

        log = capsys.readouterr().out
        assert "Ingester Start: Consignment reference TDR-2022-DNWR" in log
        assert "tar.gz saved locally as /tmp/TDR-2022-DNWR.tar.gz" in log
        assert "Ingesting document" in log
        assert "Updated judgment xml" in log
        assert "Upload Successful" in log
        assert "Ingestion complete" in log
        assert "auto_publish" not in log
        assert "Invalid XML file" not in log
        assert "No XML file found" not in log
        assert "image1.png" in log
        notify_update.assert_called()
        assert notify_update.call_count == 2
        notify_new.assert_not_called()
        annotation.assert_called_with(
            ANY,
            automated=False,
            message="Updated document submitted by TDR user",
            payload=ANY,
        )
        assert annotation.call_count == 2

    @patch("lambda_function.api_client", autospec=True)
    @patch("lambda_function.boto3.session.Session")
    @patch("lambda_function.send_new_judgment_notification")
    @patch("lambda_function.send_updated_judgment_notification")
    @patch("lambda_function.VersionAnnotation")
    def test_handler_messages_s3(
        self,
        annotation,
        notify_new,
        notify_updated,
        boto_session,
        apiclient,
        capsys,
    ):
        """Test that, with appropriate stubs, an S3 message passes through the parsing process"""
        boto_session.return_value.client.return_value.download_file = (
            create_fake_bulk_file
        )

        message = s3_message_raw
        event = {
            "Records": [{"Sns": {"Message": message}}, {"Sns": {"Message": message}}]
        }
        lambda_function.handler(event=event, context=None)

        log = capsys.readouterr().out
        assert "Ingester Start: Consignment reference BULK-0" in log
        assert "tar.gz saved locally as /tmp/BULK-0.tar.gz" in log
        assert "Ingesting document" in log
        assert "Updated judgment xml" in log
        assert "Upload Successful" in log
        assert "Ingestion complete" in log
        assert "auto_publish" in log
        assert "Invalid XML file" not in log
        assert "No XML file found" not in log
        apiclient.set_published.assert_called_with("ukut/iac/2012/82", True)
        assert apiclient.set_published.call_count == 2
        notify_new.assert_not_called()
        notify_updated.assert_not_called()
        annotation.assert_called_with(
            ANY,
            automated=True,
            message="Updated document uploaded by Find Case Law",
            payload=ANY,
        )
        assert annotation.call_count == 2


class TestLambda:
    TDR_TARBALL_PATH = os.path.join(
        os.path.dirname(__file__),
        "../aws_examples/s3/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
    )

    TARBALL_MISSING_METADATA_PATH = os.path.join(
        os.path.dirname(__file__),
        "../aws_examples/s3/te-editorial-out-int/TAR-MISSING-METADATA.tar.gz",
    )

    TARBALL_INVALID_XML_PATH = os.path.join(
        os.path.dirname(__file__),
        "../aws_examples/s3/te-editorial-out-int/TAR-INVALID-XML.tar.gz",
    )

    def test_extract_xml_file_success_tdr(self):
        filename = "TDR-2022-DNWR.xml"
        tar = tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        )
        result = lambda_function.extract_xml_file(tar, filename)
        xml = ET.XML(result.read())
        assert xml.tag == "{http://docs.oasis-open.org/legaldocml/ns/akn/3.0}akomaNtoso"

    def test_extract_xml_file_not_found_tdr(self):
        filename = "unknown.xml"
        tar = tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        )
        result = lambda_function.extract_xml_file(tar, filename)
        assert result is None

    def test_extract_xml_file_name_empty(self):
        filename = ""
        tar = tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        )
        result = lambda_function.extract_xml_file(tar, filename)
        assert result is None

    def test_extract_metadata_success_tdr(self):
        consignment_reference = "TDR-2022-DNWR"
        tar = tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        )
        result = lambda_function.extract_metadata(tar, consignment_reference)
        assert result["parameters"]["TRE"]["payload"] is not None

    def test_extract_metadata_not_found_tdr(self):
        consignment_reference = "unknown_consignment_reference"
        tar = tarfile.open(
            self.TARBALL_MISSING_METADATA_PATH,
            mode="r",
        )
        with pytest.raises(
            lambda_function.FileNotFoundException, match="Consignment Ref:"
        ):
            lambda_function.extract_metadata(tar, consignment_reference)

    def test_extract_uri_success(self):
        metadata = {
            "parameters": {
                "PARSER": {
                    "uri": "https://caselaw.nationalarchives.gov.uk/id/ewca/civ/2022/111"
                }
            }
        }
        assert lambda_function.extract_uri(metadata, "anything") == "ewca/civ/2022/111"

    def test_extract_uri_incompete(self):
        metadata = {
            "parameters": {
                "PARSER": {"uri": "https://caselaw.nationalarchives.gov.uk/id/"}
            }
        }
        assert lambda_function.extract_uri(metadata, "anything") == "failures/anything"

    def test_extract_uri_missing_key(self):
        metadata = {"parameters": {"PARSER": {}}}
        assert lambda_function.extract_uri(metadata, "anything") == "failures/anything"

    def test_extract_uri_none(self):
        metadata = {"parameters": {"PARSER": {"uri": None}}}
        assert lambda_function.extract_uri(metadata, "anything") == "failures/anything"

    def test_extract_docx_filename_success(self):
        metadata = {"parameters": {"TRE": {"payload": {"filename": "judgment.docx"}}}}
        assert (
            lambda_function.extract_docx_filename(metadata, "anything")
            == "judgment.docx"
        )

    def test_extract_docx_filename_failure(self):
        metadata = {"parameters": {"TRE": {"payload": {}}}}
        with pytest.raises(lambda_function.DocxFilenameNotFoundException):
            lambda_function.extract_docx_filename(metadata, "anything")

    @patch("lambda_function.api_client", autospec=True)
    def test_store_metadata(self, api_client):
        metadata = {
            "parameters": {
                "TDR": {
                    "Source-Organization": "Ministry of Justice",
                    "Contact-Name": "Tom King",
                    "Internal-Sender-Identifier": "TDR-2021-CF6L",
                    "Consignment-Completed-Datetime": "2021-12-16T14:54:06Z",
                    "Contact-Email": "someone@example.com",
                }
            }
        }

        api_client.set_property = MagicMock()
        lambda_function.store_metadata("uri", metadata)
        calls = [
            call("uri", name="source-organisation", value="Ministry of Justice"),
            call("uri", name="source-name", value="Tom King"),
            call("uri", name="source-email", value="someone@example.com"),
            call("uri", name="transfer-consignment-reference", value="TDR-2021-CF6L"),
            call("uri", name="transfer-received-at", value="2021-12-16T14:54:06Z"),
        ]
        api_client.set_property.assert_has_calls(calls)

    @patch("builtins.print")
    def test_store_file_success(self, mock_print):
        session = boto3.Session
        session.upload_fileobj = MagicMock()
        lambda_function.store_file(None, "folder", "filename.ext", session)
        mock_print.assert_called_with("Upload Successful folder/filename.ext")
        session.upload_fileobj.assert_called_with(None, ANY, "folder/filename.ext")

    @patch("builtins.print")
    def test_store_file_file_not_found(self, mock_print):
        session = boto3.Session
        session.upload_fileobj = MagicMock(side_effect=FileNotFoundError)
        lambda_function.store_file(None, "folder", "filename.ext", session)
        mock_print.assert_called_with("The file folder/filename.ext was not found")
        session.upload_fileobj.assert_called_with(None, ANY, "folder/filename.ext")

    @patch("builtins.print")
    def test_store_file_file_no_credentials(self, mock_print):
        session = boto3.Session
        session.upload_fileobj = MagicMock(side_effect=NoCredentialsError)
        lambda_function.store_file(None, "folder", "filename.ext", session)
        mock_print.assert_called_with("Credentials not available")
        session.upload_fileobj.assert_called_with(None, ANY, "folder/filename.ext")

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
    def test_send_new_judgment_notification(self, mock_print):
        metadata = {
            "parameters": {
                "TDR": {
                    "Source-Organization": "Ministry of Justice",
                    "Contact-Name": "Tom King",
                    "Internal-Sender-Identifier": "TDR-2021-CF6L",
                    "Consignment-Completed-Datetime": "2021-12-16T14:54:06Z",
                    "Contact-Email": "someone@example.com",
                }
            }
        }
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=ewca/2023/1/press-summary/1",
            "consignment": "TDR-2021-CF6L",
            "submitter": "Tom King, Ministry of Justice <someone@example.com>",
            "submitted_at": "2021-12-16T14:54:06Z",
            "doctype": "Press Summary",
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        lambda_function.send_new_judgment_notification(
            "ewca/2023/1/press-summary/1", metadata
        )
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )
        mock_print.assert_called_with(
            Contains("Sent new notification to test@notifications.service.gov.uk")
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
    @patch("builtins.print")
    def test_send_new_judgment_notification_with_no_tdr_section(self, mock_print):
        metadata = {}
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=ewca/2023/1/press-summary/1",
            "consignment": "unknown",
            "submitter": "unknown, unknown <unknown>",
            "submitted_at": "unknown",
            "doctype": "Press Summary",
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        lambda_function.send_new_judgment_notification(
            "ewca/2023/1/press-summary/1", metadata
        )
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )
        mock_print.assert_called_with(
            Contains("Sent new notification to test@notifications.service.gov.uk")
        )

    @patch.dict(
        os.environ,
        {"ROLLBAR_ENV": "staging"},
        clear=True,
    )
    @patch("builtins.print")
    def test_do_not_send_new_judgment_notification_on_staging(self, mock_print):
        metadata = {
            "parameters": {
                "TDR": {
                    "Source-Organization": "Ministry of Justice",
                    "Contact-Name": "Tom King",
                    "Internal-Sender-Identifier": "TDR-2021-CF6L",
                    "Consignment-Completed-Datetime": "2021-12-16T14:54:06Z",
                    "Contact-Email": "someone@example.com",
                }
            }
        }

        NotificationsAPIClient.send_email_notification = MagicMock()
        lambda_function.send_new_judgment_notification("uri", metadata)
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
    def test_send_updated_judgment_notification(self, mock_print):
        metadata = {
            "parameters": {
                "TDR": {
                    "Source-Organization": "Ministry of Justice",
                    "Contact-Name": "Tom King",
                    "Internal-Sender-Identifier": "TDR-2021-CF6L",
                    "Consignment-Completed-Datetime": "2021-12-16T14:54:06Z",
                    "Contact-Email": "someone@example.com",
                }
            }
        }
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=uri",
            "consignment": "TDR-2021-CF6L",
            "submitter": "Tom King, Ministry of Justice <someone@example.com>",
            "submitted_at": "2021-12-16T14:54:06Z",
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        lambda_function.send_updated_judgment_notification("uri", metadata)
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )
        mock_print.assert_called_with(
            Contains("Sent update notification to test@notifications.service.gov.uk")
        )

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
    def test_send_updated_judgment_notification_with_no_tdr_section(self, mock_print):
        metadata = {}
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=uri",
            "consignment": "unknown",
            "submitter": "unknown, unknown <unknown>",
            "submitted_at": "unknown",
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        lambda_function.send_updated_judgment_notification("uri", metadata)
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )
        mock_print.assert_called_with(
            Contains("Sent update notification to test@notifications.service.gov.uk")
        )

    @patch.object(lambda_function, "store_file")
    def test_copy_file_success(self, mock_store_file):
        tar = tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        )
        filename = "TDR-2022-DNWR/TDR-2022-DNWR.xml"
        session = boto3.Session
        lambda_function.store_file = MagicMock()
        lambda_function.copy_file(tar, filename, "new_filename", "uri", session)
        lambda_function.store_file.assert_called_with(ANY, ANY, ANY, ANY)

    def test_copy_file_not_found(self):
        tar = tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        )
        filename = "does_not_exist.txt"
        session = boto3.Session
        with pytest.raises(lambda_function.FileNotFoundException):
            lambda_function.copy_file(tar, filename, "new_filename", "uri", session)

    def test_create_xml_contents_success(self):
        tar = tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        )
        result = lambda_function.create_parser_log_xml(tar)
        assert result == "<error>This is the parser error log.</error>"

    @patch.object(tarfile, "open")
    def test_create_xml_contents_failure(self, mock_open_tarfile):
        tar = tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        )
        tar.extractfile = MagicMock(side_effect=KeyError)
        result = lambda_function.create_parser_log_xml(tar)
        assert result == "<error>parser.log not found</error>"

    @patch.dict(
        os.environ,
        {"PUBLIC_ASSET_BUCKET": "public-bucket", "AWS_BUCKET_NAME": "private-bucket"},
    )
    def test_update_published_documents(self):
        contents = {"Contents": [{"Key": "file1.ext"}, {"Key": "file2.ext"}]}
        s3_client = boto3.Session
        s3_client.list_objects = MagicMock(return_value=contents)
        s3_client.copy = MagicMock()
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
        lambda_function.update_published_documents("uri", s3_client)
        s3_client.copy.assert_has_calls(calls)

    def test_get_consignment_reference_success_v2(self):
        message = v2_message
        message["parameters"]["reference"] = "THIS_REF"
        result = lambda_function.get_consignment_reference(message)
        assert result == "THIS_REF"

    def test_get_consignment_reference_empty_v2(self):
        message = v2_message
        message["parameters"]["reference"] = ""
        message["parameters"][
            "bundleFileURI"
        ] = "http://172.17.0.2:4566/te-editorial-out-int/ewca_civ_2021_1881.tar.gz"
        with pytest.raises(lambda_function.InvalidMessageException):
            lambda_function.get_consignment_reference(message)

    def test_get_consignment_reference_missing_v2(self):
        message = dict(v2_message)
        del message["parameters"]["reference"]
        message["parameters"][
            "bundleFileURI"
        ] = "http://172.17.0.2:4566/te-editorial-out-int/ewca_civ_2021_1881.tar.gz"
        with pytest.raises(lambda_function.InvalidMessageException):
            lambda_function.get_consignment_reference(message)

    def test_get_consignment_reference_presigned_url_v2(self):
        message = v2_message
        message["parameters"]["reference"] = ""
        message["parameters"][
            "bundleFileURI"
        ] = "http://172.17.0.2:4566/te-editorial-out-int/ewca_civ_2021_1881.tar.gz?randomstuffafterthefilename"
        with pytest.raises(lambda_function.InvalidMessageException):
            lambda_function.get_consignment_reference(message)

    def test_malformed_message(self):
        message = {"something-unexpected": "???"}
        with pytest.raises(lambda_function.InvalidMessageException):
            lambda_function.get_consignment_reference(message)

    @patch("lambda_function.api_client", autospec=True)
    def test_update_document_xml_success(self, api_client):
        xml = ET.XML("<xml>Here's some xml</xml>")
        api_client.get_judgment_xml = MagicMock(return_value=True)
        api_client.update_document_xml = MagicMock(return_value=True)
        result = lambda_function.update_document_xml(
            "a/fake/uri",
            xml,
            {
                "parameters": {
                    "TDR": {
                        "Internal-Sender-Identifier": "TDR-2023-ABC",
                        "Contact-Name": "Test Contact",
                        "Contact-Email": "test@example.com",
                    }
                }
            },
        )
        assert result is True

    @patch("lambda_function.api_client", autospec=True)
    def test_update_document_xml_success_no_tdr(self, api_client):
        xml = ET.XML("<xml>Here's some xml</xml>")
        api_client.get_judgment_xml = MagicMock(return_value=True)
        api_client.update_document_xml = MagicMock(return_value=True)
        result = lambda_function.update_document_xml(
            "a/fake/uri",
            xml,
            {"parameters": {}},
        )
        assert result is True

    @patch("lambda_function.api_client", autospec=True)
    def test_update_document_xml_judgment_does_not_exist(self, api_client):
        xml = ET.XML("<xml>Here's some xml</xml>")
        api_client.get_judgment_xml = MagicMock(
            side_effect=MarklogicResourceNotFoundError("error")
        )
        api_client.update_document_xml = MagicMock(return_value=True)
        result = lambda_function.update_document_xml(
            "a/fake/uri",
            xml,
            {
                "parameters": {
                    "TDR": {
                        "Internal-Sender-Identifier": "TDR-2023-ABC",
                        "Contact-Name": "Test Contact",
                        "Contact-Email": "test@example.com",
                    }
                }
            },
        )
        assert result is False

    @patch("lambda_function.api_client", autospec=True)
    def test_update_document_xml_judgment_does_not_save(self, api_client):
        xml = ET.XML("<xml>Here's some xml</xml>")
        api_client.get_judgment_xml = MagicMock(return_value=True)
        api_client.update_document_xml = MagicMock(
            side_effect=MarklogicCommunicationError("error")
        )
        with pytest.raises(MarklogicCommunicationError):
            lambda_function.update_document_xml(
                "a/fake/uri",
                xml,
                {
                    "parameters": {
                        "TDR": {
                            "Internal-Sender-Identifier": "TDR-2023-ABC",
                            "Contact-Name": "Test Contact",
                            "Contact-Email": "test@example.com",
                        }
                    }
                },
            )

    @patch("lambda_function.api_client", autospec=True)
    def test_insert_document_xml_success(self, api_client):
        xml = ET.XML("<xml>Here's some xml</xml>")
        api_client.insert_document_xml = MagicMock(return_value=True)
        result = lambda_function.insert_document_xml(
            "a/fake/uri",
            xml,
            {
                "parameters": {
                    "TDR": {
                        "Internal-Sender-Identifier": "TDR-2023-ABC",
                        "Contact-Name": "Test Contact",
                        "Contact-Email": "test@example.com",
                    }
                }
            },
        )
        assert result is True

    @patch("lambda_function.api_client", autospec=True)
    def test_insert_document_xml_failure(self, api_client):
        xml = ET.XML("<xml>Here's some xml</xml>")
        api_client.insert_document_xml = MagicMock(
            side_effect=MarklogicCommunicationError("error")
        )
        with pytest.raises(MarklogicCommunicationError):
            lambda_function.insert_document_xml(
                "a/fake/uri",
                xml,
                {
                    "parameters": {
                        "TDR": {
                            "Internal-Sender-Identifier": "TDR-2023-ABC",
                            "Contact-Name": "Test Contact",
                            "Contact-Email": "test@example.com",
                        }
                    }
                },
            )

    def test_get_best_xml_with_valid_xml_file(self):
        filename = "TDR-2022-DNWR.xml"
        with tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = lambda_function.get_best_xml(
                "a/valid/uri", tar, filename, "a_consignment_reference"
            )
            assert result.__class__ == ET.Element
            assert (
                result.tag
                == "{http://docs.oasis-open.org/legaldocml/ns/akn/3.0}akomaNtoso"
            )

    def test_get_best_xml_with_invalid_xml_file(self):
        filename = "TDR-2022-DNWR.xml"
        with tarfile.open(
            self.TARBALL_INVALID_XML_PATH,
            mode="r",
        ) as tar:
            result = lambda_function.get_best_xml(
                "a/valid/uri", tar, filename, "a_consignment_reference"
            )
            assert result.__class__ == ET.Element
            assert result.tag == "error"

    def test_get_best_xml_with_failure_uri_but_valid_xml(self):
        filename = "TDR-2022-DNWR.xml"
        with tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = lambda_function.get_best_xml(
                "failures/consignment_reference",
                tar,
                filename,
                "a_consignment_reference",
            )
            assert result.__class__ == ET.Element
            assert (
                result.tag
                == "{http://docs.oasis-open.org/legaldocml/ns/akn/3.0}akomaNtoso"
            )

    def test_get_best_xml_with_failure_uri_and_missing_xml(self):
        filename = "missing_filename.xml"
        with tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = lambda_function.get_best_xml(
                "failures/consignment_reference",
                tar,
                filename,
                "a_consignment_reference",
            )
            assert result.__class__ == ET.Element
            assert result.tag == "error"

    def test_get_best_xml_with_no_xml_file(self):
        filename = "missing_filename.xml"
        with tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = lambda_function.get_best_xml(
                "failures/consignment_reference",
                tar,
                filename,
                "a_consignment_reference",
            )
            assert result.__class__ == ET.Element
            assert result.tag == "error"

    @patch("lambda_function.api_client", autospec=True)
    def test_unpublish_updated_judgment(self, api_client):
        uri = "a/fake/uri"
        api_client.set_published = MagicMock()
        lambda_function.unpublish_updated_judgment(uri)
        api_client.set_published.assert_called_with(uri, False)

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

        event = {"Records": [{"Sns": {"Message": my_raw}}]}
        message = lambda_function.Message.from_event(event)
        mock_s3_client = MagicMock()
        message.save_s3_response(None, mock_s3_client)
        mock_s3_client.download_file.assert_called_with(
            ANY, "2010 Reported/[2010]/1.tar.gz", ANY
        )

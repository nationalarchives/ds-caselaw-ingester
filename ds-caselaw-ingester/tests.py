import os
import tarfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import ANY, MagicMock, call, patch

import boto3
from botocore.exceptions import NoCredentialsError
from callee import Contains
from caselawclient.Client import api_client
from notifications_python_client.notifications import NotificationsAPIClient

from . import lambda_function


class LambdaTest(unittest.TestCase):

    TDR_TARBALL_PATH = os.path.join(
        os.path.dirname(__file__),
        "../aws_examples/s3/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
    )

    EDGE_TARBALL_PATH = os.path.join(
        os.path.dirname(__file__),
        "../aws_examples/s3/te-editorial-out-int/ewca_civ_2021_1881.tar.gz",
    )

    TARBALL_MISSING_METADATA_PATH = os.path.join(
        os.path.dirname(__file__),
        "../aws_examples/s3/te-editorial-out-int/TAR-MISSING-METADATA.tar.gz",
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

    def test_extract_xml_file_success_edge(self):
        filename = "judgment.xml"
        tar = tarfile.open(
            self.EDGE_TARBALL_PATH,
            mode="r",
        )
        result = lambda_function.extract_xml_file(tar, filename)
        # XML document may not be valid in an "edge" tarball, so just check the file is there
        assert result is not None

    def test_extract_xml_file_not_found_tdr(self):
        filename = "unknown.xml"
        tar = tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        )
        result = lambda_function.extract_xml_file(tar, filename)
        assert result is None

    def test_extract_xml_file_not_found_edge(self):
        filename = "unknown.xml"
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

    def test_extract_metadata_success_edge(self):
        consignment_reference = "name_of_tarfile"
        tar = tarfile.open(
            self.EDGE_TARBALL_PATH,
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
        with self.assertRaisesRegex(
            lambda_function.FileNotFoundException, "Consignment Ref:"
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
        with self.assertRaises(lambda_function.DocxFilenameNotFoundException):
            lambda_function.extract_docx_filename(metadata, "anything")

    def test_store_metadata(self):
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
        session.upload_fileobj.assert_called_with(None, None, "folder/filename.ext")

    @patch("builtins.print")
    def test_store_file_file_not_found(self, mock_print):
        session = boto3.Session
        session.upload_fileobj = MagicMock(side_effect=FileNotFoundError)
        lambda_function.store_file(None, "folder", "filename.ext", session)
        mock_print.assert_called_with("The file folder/filename.ext was not found")
        session.upload_fileobj.assert_called_with(None, None, "folder/filename.ext")

    @patch("builtins.print")
    def test_store_file_file_no_credentials(self, mock_print):
        session = boto3.Session
        session.upload_fileobj = MagicMock(side_effect=NoCredentialsError)
        lambda_function.store_file(None, "folder", "filename.ext", session)
        mock_print.assert_called_with("Credentials not available")
        session.upload_fileobj.assert_called_with(None, None, "folder/filename.ext")

    @patch.dict(
        os.environ,
        {
            "NOTIFY_API_KEY": "ingester-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "EDITORIAL_UI_BASE_URL": "http://editor.url/",
            "NOTIFY_EDITORIAL_ADDRESS": "test@notifications.service.gov.uk",
            "NOTIFY_NEW_JUDGMENT_TEMPLATE_ID": "template-id",
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
            "url": "http://editor.url/detail?judgment_uri=uri",
            "consignment": "TDR-2021-CF6L",
            "submitter": "Tom King, Ministry of Justice <someone@example.com>",
            "submitted_at": "2021-12-16T14:54:06Z",
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        lambda_function.send_new_judgment_notification("uri", metadata)
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )
        mock_print.assert_called_with(
            Contains("Sent notification to test@notifications.service.gov.uk")
        )

    @patch.dict(
        os.environ,
        {
            "NOTIFY_API_KEY": "ingester-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "EDITORIAL_UI_BASE_URL": "http://editor.url/",
            "NOTIFY_EDITORIAL_ADDRESS": "test@notifications.service.gov.uk",
            "NOTIFY_UPDATED_JUDGMENT_TEMPLATE_ID": "template-id",
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
            Contains("Sent notification to test@notifications.service.gov.uk")
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
        with self.assertRaises(lambda_function.FileNotFoundException):
            lambda_function.copy_file(tar, filename, "new_filename", "uri", session)

    @patch.dict(
        os.environ,
        {
            "MAX_RETRIES": "1",
            "SQS_QUEUE_URL": "http://172.17.0.2:4566/000000000000/retry-queue",
        },
    )
    def test_send_retry_message_success(self):
        message = {
            "consignment-reference": "TDR-2022-DNWR",
            "s3-folder-url": "http://172.17.0.2:4566/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
            "consignment-type": "judgment",
            "number-of-retries": 0,
        }
        sqs_client = boto3.Session
        sqs_client.send_message = MagicMock()
        lambda_function.send_retry_message(message, sqs_client)
        expected_message = (
            '{"consignment-reference": "TDR-2022-DNWR", "s3-folder-url": "", '
            '"consignment-type": "judgment", "number-of-retries": 1}'
        )
        sqs_client.send_message.assert_called_with(
            QueueUrl="http://172.17.0.2:4566/000000000000/retry-queue",
            MessageBody=expected_message,
        )

    @patch.dict(
        os.environ,
        {"MAX_RETRIES": "1"},
    )
    def test_send_retry_message_failure(self):
        message = {
            "consignment-reference": "TDR-2022-DNWR",
            "s3-folder-url": "http://172.17.0.2:4566/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
            "consignment-type": "judgment",
            "number-of-retries": 1,
        }
        sqs_client = boto3.Session
        with self.assertRaises(lambda_function.MaximumRetriesExceededException):
            lambda_function.send_retry_message(message, sqs_client)

    def test_create_error_xml_contents_success(self):
        tar = tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        )
        result = lambda_function.create_error_xml_contents(tar)
        assert result == "<error>This is the parser error log.</error>"

    @patch.object(tarfile, "open")
    def test_create_error_xml_contents_failure(self, mock_open_tarfile):
        tar = tarfile.open(
            self.TDR_TARBALL_PATH,
            mode="r",
        )
        tar.extractfile = MagicMock(side_effect=KeyError)
        result = lambda_function.create_error_xml_contents(tar)
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
                {"ACL": "public-read"},
            ),
            call(
                {"Bucket": "private-bucket", "Key": "file2.ext"},
                "public-bucket",
                "file2.ext",
                {"ACL": "public-read"},
            ),
        ]
        lambda_function.update_published_documents("uri", s3_client)
        s3_client.copy.assert_has_calls(calls)

    def test_get_consignment_reference_success(self):
        message = {
            "consignment-reference": "TDR-2022-DNWR",
            "s3-folder-url": "http://172.17.0.2:4566/te-editorial-out-int/ewca_civ_2021_1881.tar.gz",
        }
        result = lambda_function.get_consignment_reference(message)
        assert result == "TDR-2022-DNWR"

    def test_get_consignment_reference_empty(self):
        message = {
            "consignment-reference": "",
            "s3-folder-url": "http://172.17.0.2:4566/te-editorial-out-int/ewca_civ_2021_1881.tar.gz",
        }
        result = lambda_function.get_consignment_reference(message)
        assert result == "ewca_civ_2021_1881"

    def test_get_consignment_reference_missing(self):
        message = {
            "s3-folder-url": "http://172.17.0.2:4566/te-editorial-out-int/ewca_civ_2021_1881.tar.gz"
        }
        result = lambda_function.get_consignment_reference(message)
        assert result == "ewca_civ_2021_1881"

    def test_malformed_message(self):
        message = {"something-unexpected": "???"}
        with self.assertRaises(lambda_function.InvalidMessageException):
            lambda_function.get_consignment_reference(message)

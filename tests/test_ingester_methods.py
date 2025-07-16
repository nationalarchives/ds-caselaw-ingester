import os
import tarfile
import xml.etree.ElementTree as ET
from unittest.mock import ANY, MagicMock, patch

import boto3
import pytest
from botocore.exceptions import NoCredentialsError
from caselawclient.models.utilities.aws import S3PrefixString
from lxml.etree import _Element as lxmlElement

from src.ds_caselaw_ingester import exceptions, ingester

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


class TestIngesterExtractMetadataMethod:
    def test_extract_metadata_success_tdr(self):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            consignment_reference = "TDR-2022-DNWR"
            result = ingester.extract_metadata(tar, consignment_reference)
            assert result["parameters"]["TRE"]["payload"] is not None

    def test_extract_metadata_not_found_tdr(self):
        with tarfile.open(
            TARBALL_MISSING_METADATA_PATH,
            mode="r",
        ) as tar:
            consignment_reference = "unknown_consignment_reference"
            with pytest.raises(exceptions.FileNotFoundException, match="Consignment Ref:"):
                ingester.extract_metadata(tar, consignment_reference)


class TestIngesterCopyFileMethod:
    @patch.object(ingester, "store_file")
    def test_copy_file_success(self, mock_store_file):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            filename = "TDR-2022-DNWR/TDR-2022-DNWR.xml"
            session = boto3.Session
            ingester.store_file = MagicMock()
            ingester.copy_file(tar, filename, "bucket", "new_filename", "uri", session)
            ingester.store_file.assert_called_with(
                file=ANY,
                destination_bucket="bucket",
                destination_folder="uri",
                destination_filename="new_filename",
                s3_client=session,
            )

    def test_copy_file_not_found(self):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            filename = "does_not_exist.txt"
            session = boto3.Session
            with pytest.raises(exceptions.FileNotFoundException):
                ingester.copy_file(tar, filename, "bucket", "new_filename", "uri", session)


class TestIngesterStoreFileMethod:
    @patch("builtins.print")
    def test_store_file_success(self, mock_print):
        session = boto3.Session
        session.upload_fileobj = MagicMock()
        ingester.store_file(
            file=None,
            destination_bucket="bucket",
            destination_folder=S3PrefixString("folder/"),
            destination_filename="filename.ext",
            s3_client=session,
        )
        mock_print.assert_called_with("Upload Successful folder/filename.ext")
        session.upload_fileobj.assert_called_with(None, ANY, "folder/filename.ext")

    @patch("builtins.print")
    def test_store_file_file_not_found(self, mock_print):
        session = boto3.Session
        session.upload_fileobj = MagicMock(side_effect=FileNotFoundError)
        ingester.store_file(
            file=None,
            destination_bucket="bucket",
            destination_folder=S3PrefixString("folder/"),
            destination_filename="filename.ext",
            s3_client=session,
        )
        mock_print.assert_called_with("The file folder/filename.ext was not found")
        session.upload_fileobj.assert_called_with(None, ANY, "folder/filename.ext")

    @patch("builtins.print")
    def test_store_file_file_no_credentials(self, mock_print):
        session = boto3.Session
        session.upload_fileobj = MagicMock(side_effect=NoCredentialsError)
        ingester.store_file(
            file=None,
            destination_bucket="bucket",
            destination_folder=S3PrefixString("folder/"),
            destination_filename="filename.ext",
            s3_client=session,
        )
        mock_print.assert_called_with("Credentials not available")
        session.upload_fileobj.assert_called_with(None, ANY, "folder/filename.ext")


class TestIngesterExtractXMLFileMethod:
    def test_extract_xml_file_success_tdr(self):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            filename = "TDR-2022-DNWR.xml"
            result = ingester.extract_xml_file(tar, filename)
            xml = ET.XML(result.read())
            assert xml.tag == "{http://docs.oasis-open.org/legaldocml/ns/akn/3.0}akomaNtoso"

    def test_extract_xml_file_not_found_tdr(self):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            filename = "unknown.xml"
            result = ingester.extract_xml_file(tar, filename)
            assert result is None

    def test_extract_xml_file_name_empty(self):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            filename = ""
            result = ingester.extract_xml_file(tar, filename)
            assert result is None


class TestIngesterCreateParserLogMethod:
    def test_create_xml_contents_success(self):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = ingester.create_parser_log_xml(tar)
            assert result == b"<error>This is the parser error log.</error>"

    @patch.object(tarfile, "open")
    def test_create_xml_contents_failure(self, mock_open_tarfile):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            tar.extractfile = MagicMock(side_effect=KeyError)
            result = ingester.create_parser_log_xml(tar)
            assert result == b"<error>parser.log not found</error>"


class TestIngesterGetBestXMLMethod:
    def test_get_best_xml_with_valid_xml_file(self):
        filename = "TDR-2022-DNWR.xml"
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = ingester.get_best_xml(tar, filename, "a_consignment_reference")
            assert isinstance(result, lxmlElement)
            assert result.tag == "{http://docs.oasis-open.org/legaldocml/ns/akn/3.0}akomaNtoso"

    def test_get_best_xml_with_invalid_xml_file(self):
        filename = "TDR-2022-DNWR.xml"
        with tarfile.open(
            TARBALL_INVALID_XML_PATH,
            mode="r",
        ) as tar:
            result = ingester.get_best_xml(tar, filename, "a_consignment_reference")
            assert isinstance(result, lxmlElement)
            assert result.tag == "error"

    def test_get_best_xml_with_failure_uri_but_valid_xml(self):
        filename = "TDR-2022-DNWR.xml"
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = ingester.get_best_xml(
                tar,
                filename,
                "a_consignment_reference",
            )
            assert isinstance(result, lxmlElement)
            assert result.tag == "{http://docs.oasis-open.org/legaldocml/ns/akn/3.0}akomaNtoso"

    def test_get_best_xml_with_failure_uri_and_missing_xml(self):
        filename = "missing_filename.xml"
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = ingester.get_best_xml(
                tar,
                filename,
                "a_consignment_reference",
            )
            assert isinstance(result, lxmlElement)
            assert result.tag == "error"

    def test_get_best_xml_with_no_xml_file(self):
        filename = "missing_filename.xml"
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = ingester.get_best_xml(
                tar,
                filename,
                "a_consignment_reference",
            )
            assert isinstance(result, lxmlElement)
            assert result.tag == "error"


class TestIngesterExtractDocxFilenameMethod:
    def test_extract_docx_filename_success(self):
        metadata = {"parameters": {"TRE": {"payload": {"filename": "judgment.docx"}}}}
        assert ingester.extract_docx_filename(metadata, "anything") == "judgment.docx"

    def test_extract_docx_filename_no_docx_provided(self):
        """Reparsed documents do not have a docx file and have the metadata set to None"""
        metadata = {"parameters": {"TRE": {"payload": {"filename": None}}}}
        assert ingester.extract_docx_filename(metadata, "anything") is None

    def test_extract_docx_filename_failure(self):
        metadata = {"parameters": {"TRE": {"payload": {}}}}
        with pytest.raises(exceptions.DocxFilenameNotFoundException):
            ingester.extract_docx_filename(metadata, "anything")

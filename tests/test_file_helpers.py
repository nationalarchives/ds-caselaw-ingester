import logging
import os
import tarfile
from unittest.mock import ANY, MagicMock, patch

import boto3
import lxml.etree as ET
import pytest
from botocore.exceptions import NoCredentialsError
from caselawclient.models.utilities.aws import S3PrefixString
from caselawclient.xml_helpers import Element

from src.ds_caselaw_ingester import exceptions, file_helpers

from .helpers import assert_log_has_message

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


class TestFileHelpersExtractMetadataMethod:
    def test_extract_metadata_success_tdr(self):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            consignment_reference = "TDR-2022-DNWR"
            result = file_helpers.extract_metadata(tar, consignment_reference)
            assert result["parameters"]["TRE"]["payload"] is not None

    def test_extract_metadata_not_found_tdr(self):
        with tarfile.open(
            TARBALL_MISSING_METADATA_PATH,
            mode="r",
        ) as tar:
            consignment_reference = "unknown_consignment_reference"
            with pytest.raises(exceptions.FileNotFoundException, match="Consignment Ref:"):
                file_helpers.extract_metadata(tar, consignment_reference)


class TestFileHelpersCopyFileMethod:
    @patch.object(file_helpers, "store_file")
    def test_copy_file_success(self, mock_store_file):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            filename = "TDR-2022-DNWR/TDR-2022-DNWR.xml"
            session = boto3.Session
            file_helpers.copy_file(tar, filename, "bucket", "new_filename", "uri", session)
            mock_store_file.assert_called_with(
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
                file_helpers.copy_file(tar, filename, "bucket", "new_filename", "uri", session)


class TestFileHelpersStoreFileMethod:
    @pytest.mark.parametrize(
        "side_effect,expected_level,expected_message",
        [
            (None, logging.INFO, "Upload Successful folder/filename.ext"),
            (FileNotFoundError, logging.ERROR, "The file folder/filename.ext was not found"),
            (NoCredentialsError, logging.ERROR, "Credentials not available"),
        ],
    )
    def test_store_file(self, caplog: pytest.LogCaptureFixture, side_effect, expected_level, expected_message):
        caplog.set_level(logging.DEBUG, logger="ingester")
        session = boto3.Session
        session.upload_fileobj = MagicMock(side_effect=side_effect)
        file_helpers.store_file(
            file=None,
            destination_bucket="bucket",
            destination_folder=S3PrefixString("folder/"),
            destination_filename="filename.ext",
            s3_client=session,
        )
        assert_log_has_message(caplog, expected_message, expected_level)
        session.upload_fileobj.assert_called_with(None, ANY, "folder/filename.ext")


class TestFileHelpersExtractXMLFileMethod:
    def test_extract_xml_file_success_tdr(self):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            filename = "TDR-2022-DNWR.xml"
            result = file_helpers.extract_xml_file(tar, filename)
            xml = ET.XML(result.read())
            assert xml.tag == "{http://docs.oasis-open.org/legaldocml/ns/akn/3.0}akomaNtoso"

    def test_extract_xml_file_not_found_tdr(self):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            filename = "unknown.xml"
            result = file_helpers.extract_xml_file(tar, filename)
            assert result is None

    def test_extract_xml_file_name_empty(self):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            filename = ""
            result = file_helpers.extract_xml_file(tar, filename)
            assert result is None


class TestFileHelpersCreateParserLogMethod:
    def test_create_xml_contents_success(self):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = file_helpers.create_parser_log_xml(tar)
            assert result == b"<error>This is the parser error log.</error>"

    @patch.object(tarfile, "open")
    def test_create_xml_contents_failure(self, mock_open_tarfile):
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            tar.extractfile = MagicMock(side_effect=KeyError)
            result = file_helpers.create_parser_log_xml(tar)
            assert result == b"<error>parser.log not found</error>"


class TestFileHelpersGetBestXMLMethod:
    def test_get_best_xml_with_valid_xml_file(self):
        filename = "TDR-2022-DNWR.xml"
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = file_helpers.get_best_xml(tar, filename, "a_consignment_reference")
            assert result.__class__ == Element
            assert result.tag == "{http://docs.oasis-open.org/legaldocml/ns/akn/3.0}akomaNtoso"

    def test_get_best_xml_with_invalid_xml_file(self):
        filename = "TDR-2022-DNWR.xml"
        with tarfile.open(
            TARBALL_INVALID_XML_PATH,
            mode="r",
        ) as tar:
            result = file_helpers.get_best_xml(tar, filename, "a_consignment_reference")
            assert result.__class__ == Element
            assert result.tag == "error"

    def test_get_best_xml_with_failure_uri_but_valid_xml(self):
        filename = "TDR-2022-DNWR.xml"
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = file_helpers.get_best_xml(
                tar,
                filename,
                "a_consignment_reference",
            )
            assert result.__class__ == Element
            assert result.tag == "{http://docs.oasis-open.org/legaldocml/ns/akn/3.0}akomaNtoso"

    def test_get_best_xml_with_failure_uri_and_missing_xml(self):
        filename = "missing_filename.xml"
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = file_helpers.get_best_xml(
                tar,
                filename,
                "a_consignment_reference",
            )
            assert result.__class__ == Element
            assert result.tag == "error"

    def test_get_best_xml_with_no_xml_file(self):
        filename = "missing_filename.xml"
        with tarfile.open(
            TDR_TARBALL_PATH,
            mode="r",
        ) as tar:
            result = file_helpers.get_best_xml(
                tar,
                filename,
                "a_consignment_reference",
            )
            assert result.__class__ == Element
            assert result.tag == "error"


class TestFileHelpersExtractDocxFilenameMethod:
    def test_extract_source_filename_success(self):
        metadata = {"parameters": {"TRE": {"payload": {"filename": "judgment.docx"}}}}
        assert file_helpers.extract_source_filename(metadata, "anything") == "judgment.docx"

    def test_extract_source_filename_no_docx_provided(self):
        """Reparsed documents do not have a docx file and have the metadata set to None"""
        metadata = {"parameters": {"TRE": {"payload": {"filename": None}}}}
        assert file_helpers.extract_source_filename(metadata, "anything") is None

    def test_extract_source_filename_failure(self):
        metadata = {"parameters": {"TRE": {"payload": {}}}}
        with pytest.raises(exceptions.DocxFilenameNotFoundException):
            file_helpers.extract_source_filename(metadata, "anything")

import os
import tarfile
import unittest
import xml.etree.ElementTree as ET

from . import lambda_function


class LambdaTest(unittest.TestCase):
    def test_extract_xml_file_success(self):
        consignment_reference = "TDR-2022-DNWR"
        filename = "TDR-2022-DNWR.xml"
        tar = tarfile.open(
            os.path.join(
                os.path.dirname(__file__),
                "../aws_examples/s3/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
            ),
            mode="r",
        )
        result = lambda_function.extract_xml_file(tar, filename, consignment_reference)
        xml = ET.XML(result.read())
        assert xml.tag == "{http://docs.oasis-open.org/legaldocml/ns/akn/3.0}akomaNtoso"

    def test_extract_xml_file_not_found(self):
        consignment_reference = "TDR-2022-DNWR"
        filename = "unknown.xml"
        tar = tarfile.open(
            os.path.join(
                os.path.dirname(__file__),
                "../aws_examples/s3/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
            ),
            mode="r",
        )
        result = lambda_function.extract_xml_file(tar, filename, consignment_reference)
        assert result is None

    def test_extract_metadata_success(self):
        consignment_reference = "TDR-2022-DNWR"
        tar = tarfile.open(
            os.path.join(
                os.path.dirname(__file__),
                "../aws_examples/s3/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
            ),
            mode="r",
        )
        result = lambda_function.extract_metadata(tar, consignment_reference)
        assert result["producer"]["type"] == "judgment"

    def test_extract_metadata_not_found(self):
        consignment_reference = "unknown_consignment_reference"
        tar = tarfile.open(
            os.path.join(
                os.path.dirname(__file__),
                "../aws_examples/s3/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
            ),
            mode="r",
        )
        with self.assertRaises(lambda_function.FileNotFoundException):
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

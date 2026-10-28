import io
import json
import os
import tarfile

import pytest

from src.ds_caselaw_ingester import file_helpers
from src.ds_caselaw_ingester.exceptions import InvalidMetadataException
from src.ds_caselaw_ingester.parser_metadata import validate_document_processing_metadata

TDR_TARBALL_PATH = os.path.join(
    os.path.dirname(__file__),
    "../aws_examples/s3/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
)


def minimal_valid_metadata() -> dict:
    return {
        "parameters": {
            "PARSER": {"documentType": "judgment"},
            "TRE": {"reference": "TRE-TEST", "payload": {"xml": "test.xml"}},
        },
    }


class TestValidateDocumentProcessingMetadata:
    def test_accepts_minimal_valid_metadata(self):
        data = minimal_valid_metadata()
        assert validate_document_processing_metadata(data, consignment_reference="TEST-1") == data

    def test_rejects_non_object_metadata(self):
        with pytest.raises(InvalidMetadataException, match="Consignment Ref: TEST-2"):
            validate_document_processing_metadata([], consignment_reference="TEST-2")

    def test_rejects_missing_document_type(self):
        data = {"parameters": {"PARSER": {}}}
        with pytest.raises(InvalidMetadataException, match="documentType"):
            validate_document_processing_metadata(data, consignment_reference="TEST-3")

    def test_rejects_invalid_document_type(self):
        data = {"parameters": {"PARSER": {"documentType": "not-a-real-type"}}}
        with pytest.raises(InvalidMetadataException, match="Consignment Ref: TEST-4"):
            validate_document_processing_metadata(data, consignment_reference="TEST-4")

    def test_rejects_invalid_metadata_field_source(self):
        data = minimal_valid_metadata()
        data["parameters"]["PARSER"]["metadata_fields"] = [
            {
                "name": "title",
                "value": "Example",
                "source": "invalid-source",
                "timestamp": "2025-12-17T18:00:00+00:00",
            },
        ]
        with pytest.raises(InvalidMetadataException, match="Consignment Ref: TEST-5"):
            validate_document_processing_metadata(data, consignment_reference="TEST-5")

    def test_rejects_malformed_parser_run_id_uuid(self):
        data = minimal_valid_metadata()
        data["parameters"]["PARSER"]["parser_run_id"] = "not-a-uuid"
        with pytest.raises(InvalidMetadataException, match="uuid"):
            validate_document_processing_metadata(data, consignment_reference="TEST-6")

    def test_rejects_malformed_parser_date(self):
        data = minimal_valid_metadata()
        data["parameters"]["PARSER"]["date"] = "not-a-date"
        with pytest.raises(InvalidMetadataException, match="Consignment Ref: TEST-7"):
            validate_document_processing_metadata(data, consignment_reference="TEST-7")

    def test_rejects_malformed_parser_uri(self):
        data = minimal_valid_metadata()
        data["parameters"]["PARSER"]["uri"] = "not a uri"
        with pytest.raises(InvalidMetadataException, match="Consignment Ref: TEST-8"):
            validate_document_processing_metadata(data, consignment_reference="TEST-8")

    def test_rejects_malformed_metadata_field_timestamp(self):
        data = minimal_valid_metadata()
        data["parameters"]["PARSER"]["metadata_fields"] = [
            {
                "name": "title",
                "value": "Example",
                "source": "document",
                "timestamp": "not-a-datetime",
            },
        ]
        with pytest.raises(InvalidMetadataException, match="Consignment Ref: TEST-9"):
            validate_document_processing_metadata(data, consignment_reference="TEST-9")


class TestExtractMetadataValidation:
    def test_extract_metadata_validates_example_tarball(self):
        with tarfile.open(TDR_TARBALL_PATH, mode="r") as tar:
            result = file_helpers.extract_metadata(tar, "TDR-2022-DNWR")
        assert result["parameters"]["PARSER"]["documentType"] == "judgment"

    def test_extract_metadata_rejects_invalid_metadata_in_tar(self, tmp_path):
        metadata = json.dumps({"parameters": {"PARSER": {}}}).encode("utf-8")
        metadata_name = "CONSIGN/CONSIGN-metadata.json"
        tar_path = tmp_path / "invalid-metadata.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            info = tarfile.TarInfo(name=metadata_name)
            info.size = len(metadata)
            tar.addfile(info, io.BytesIO(metadata))

        with (
            tarfile.open(tar_path, mode="r") as tar,
            pytest.raises(InvalidMetadataException, match="Consignment Ref: CONSIGN"),
        ):
            file_helpers.extract_metadata(tar, "CONSIGN")

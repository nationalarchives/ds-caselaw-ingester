import copy
import json
from unittest.mock import Mock, patch

from pytest import fixture

from src.ds_caselaw_ingester import ingester, lambda_function

from .helpers import create_fake_bulk_file, create_fake_tdr_file

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
            "originator": "TDR",
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
        },
    ],
}
v2_message = json.loads(v2_message_raw)
s3_message_raw = json.dumps(s3_message)


@fixture
@patch(
    "src.ds_caselaw_ingester.lambda_function.Ingest.save_tar_file_in_s3",
    return_value="/tmp/TDR-2022-DNWR.tar.gz",
)
@patch("src.ds_caselaw_ingester.ingester.uuid4")
def v2_ingest(mock_uuid4, fake_s3):
    mock_uuid4.return_value = "v2-a1b2-c3d4"
    create_fake_tdr_file()
    return ingester.Ingest(
        message=lambda_function.Message.from_message(v2_message),
        destination_bucket="bucket",
        api_client=Mock(),
        s3_client=Mock(),
    )


@fixture
@patch("src.ds_caselaw_ingester.lambda_function.Ingest.save_tar_file_in_s3", return_value="/tmp/BULK-0.tar.gz")
@patch("src.ds_caselaw_ingester.ingester.uuid4")
def s3_ingest(mock_uuid4, fake_s3):
    mock_uuid4.return_value = "s3-a1b2-c3d4"
    create_fake_bulk_file()
    return ingester.Ingest(
        message=lambda_function.Message.from_message(s3_message),
        destination_bucket="bucket",
        api_client=Mock(),
        s3_client=Mock(),
    )


@fixture
@patch(
    "src.ds_caselaw_ingester.lambda_function.Ingest.save_tar_file_in_s3",
    return_value="/tmp/TDR-2022-DNWR.tar.gz",
)
def fcl_ingest(fake_s3):
    "Fake a FCL reparse message (badly)"
    new_message = copy.deepcopy(v2_message)
    new_message["parameters"]["originator"] = "FCL"

    return ingester.Ingest(
        message=lambda_function.Message.from_message(new_message),
        destination_bucket="bucket",
        api_client=Mock(),
        s3_client=Mock(),
    )

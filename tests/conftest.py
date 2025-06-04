import copy
import json
import tarfile
from unittest.mock import Mock, PropertyMock, patch

from caselawclient.types import DocumentURIString
from pytest import fixture

from src.ds_caselaw_ingester import ingester, lambda_function

from .helpers import create_fake_bulk_file, create_fake_tdr_file


def setup_api_client():
    return Mock()


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

error_message_raw = v2_message_raw.replace("TDR-2022-DNWR", "TDR-2025-CN7V")

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
    "src.ds_caselaw_ingester.ingester.Ingest.database_location",
    new_callable=PropertyMock,
    return_value=(DocumentURIString("v2-a1b2-c3d4"), False),
)
def v2_ingest(fake_location):
    create_fake_tdr_file()
    with tarfile.open("/tmp/TDR-2022-DNWR.tar.gz", mode="r") as tarfile_reader:
        return ingester.Ingest(
            message=lambda_function.Message.from_message(v2_message),
            tarfile_reader=tarfile_reader,
            destination_bucket="bucket",
            destination_tar_filename="/tmp/TDR-2022-DNWR.tar.gz",
            api_client=setup_api_client(),
            s3_client=Mock(),
        )


@fixture
@patch(
    "src.ds_caselaw_ingester.ingester.Ingest.database_location",
    new_callable=PropertyMock,
    return_value=(DocumentURIString("s3-a1b2-c3d4"), True),
)
def s3_ingest(fake_determine_uri):  # TODO DRAGON
    create_fake_bulk_file()
    with tarfile.open("/tmp/BULK-0.tar.gz", mode="r") as tarfile_reader:
        return ingester.Ingest(
            message=lambda_function.Message.from_message(s3_message),
            tarfile_reader=tarfile_reader,
            destination_bucket="bucket",
            destination_tar_filename="/tmp/BULK-0.tar.gz",
            api_client=setup_api_client(),
            s3_client=Mock(),
        )


@fixture
@patch(
    "src.ds_caselaw_ingester.ingester.Ingest.database_location",
    new_callable=PropertyMock,
    return_value=(DocumentURIString("s3-a1b2-c3d4"), True),
)
def fcl_ingest(fake_determine_uri):
    "Fake a FCL reparse message (badly)"
    new_message = copy.deepcopy(v2_message)
    new_message["parameters"]["originator"] = "FCL"
    with tarfile.open("/tmp/TDR-2022-DNWR.tar.gz", mode="r") as tarfile_reader:
        return ingester.Ingest(
            message=lambda_function.Message.from_message(new_message),
            tarfile_reader=tarfile_reader,
            destination_bucket="bucket",
            destination_tar_filename="/tmp/TDR-2022-DNWR.tar.gz",
            api_client=setup_api_client(),
            s3_client=Mock(),
        )

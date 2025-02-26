"""This file contains code which is used to understand an incoming message and decide what to do with it."""

import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Optional
from urllib.parse import unquote_plus

import boto3
import boto3.s3
import rollbar
from caselawclient.Client import (
    DEFAULT_USER_AGENT,
    MarklogicApiClient,
)
from dotenv import load_dotenv
from exceptions import InvalidMessageException
from ingester import Ingest
from mypy_boto3_s3.client import S3Client
from mypy_boto3_s3.type_defs import CopySourceTypeDef
from mypy_boto3_sqs.client import SQSClient

logger = logging.getLogger("ingester")
logger.setLevel(logging.DEBUG)

load_dotenv()

rollbar.init(os.getenv("ROLLBAR_TOKEN"), environment=os.getenv("ROLLBAR_ENV"))

MARKLOGIC_HOST: str = os.environ["MARKLOGIC_HOST"]
MARKLOGIC_USER: str = os.environ["MARKLOGIC_USER"]
MARKLOGIC_PASSWORD: str = os.environ["MARKLOGIC_PASSWORD"]
MARKLOGIC_USE_HTTPS: bool = bool(os.getenv("MARKLOGIC_USE_HTTPS", default=False))

AWS_BUCKET_NAME: str = os.environ["AWS_BUCKET_NAME"]
PUBLIC_ASSET_BUCKET: str = os.environ["PUBLIC_ASSET_BUCKET"]

api_client = MarklogicApiClient(
    host=MARKLOGIC_HOST,
    username=MARKLOGIC_USER,
    password=MARKLOGIC_PASSWORD,
    use_https=MARKLOGIC_USE_HTTPS,
    user_agent=f"ds-caselaw-ingester/unknown {DEFAULT_USER_AGENT}",
)


class Message(ABC):
    @classmethod
    def from_message(cls, message: dict) -> "Message":
        if message.get("Records", [{}])[0].get("eventSource") == "aws:s3":
            return S3Message(message["Records"][0])
        elif "parameters" in message:
            return V2Message(message)
        else:
            raise InvalidMessageException(f"Did not recognise message type. {message}")

    def __init__(self, message) -> None:
        self.message = message

    @property
    @abstractmethod
    def originator(self) -> str: ...

    def update_consignment_reference(self, new_ref: str) -> None:
        return

    @abstractmethod
    def get_consignment_reference(self) -> str: ...

    @abstractmethod
    def save_s3_response(self, s3_client: S3Client) -> str: ...


class V2Message(Message):
    @property
    def originator(self) -> str:
        return self.message.get("parameters", {}).get("originator")

    def get_consignment_reference(self) -> str:
        """A strange quirk: the consignment reference we recieve from the V2 message is
        of the form TDR-2000-123, but the consignment reference inside the document is
        of the form TRE-TDR-2000-123. The folder in the .tar.gz file is TDR-2000-123,
        it reflects the V2 message format, not the format found within the tar.gz"""
        result = self.message.get("parameters", {}).get("reference")
        if result:
            return result

        raise InvalidMessageException("Malformed v2 message, please supply a reference")

    def save_s3_response(self, s3_client: S3Client) -> str:
        s3_bucket = self.message.get("parameters", {}).get("s3Bucket")
        s3_key = self.message.get("parameters", {}).get("s3Key")
        reference = self.get_consignment_reference()
        local_tar_filename = os.path.join("/tmp", f"{reference}.tar.gz")
        s3_client.download_file(s3_bucket, s3_key, local_tar_filename)
        if not os.path.exists(local_tar_filename):
            raise RuntimeError(f"File {local_tar_filename} not created")
        print(f"tar.gz saved locally as {local_tar_filename}")
        return local_tar_filename


class S3Message(V2Message):
    """An SNS message generated directly by adding a file to an S3 bucket"""

    def __init__(self, *args, **kwargs) -> None:
        self._consignment: Optional[str] = None
        super().__init__(*args, **kwargs)

    @property
    def originator(self) -> str:
        return "FCL S3"

    def get_consignment_reference(self) -> str:
        """We use the filename as a first draft of the consignment reference,
        but later update it with the value from the tar gz. Note that this
        behaviour is totally inconsistent with the behaviour of the V2 message
        where the consignment reference in the metadata is ignored."""
        if self._consignment:
            return self._consignment
        return self.message["s3"]["object"]["key"].split("/")[-1].partition(".")[0]

    def update_consignment_reference(self, new_ref: str) -> None:
        self._consignment = new_ref

    def save_s3_response(self, s3_client: S3Client) -> str:
        s3_key = unquote_plus(self.message["s3"]["object"]["key"])
        s3_bucket = self.message["s3"]["bucket"]["name"]
        reference = self.get_consignment_reference()
        local_tar_filename = os.path.join("/tmp", f"{reference}.tar.gz")
        s3_client.download_file(s3_bucket, s3_key, local_tar_filename)
        if not os.path.exists(local_tar_filename):
            raise RuntimeError(f"File {local_tar_filename} not created")
        print(f"tar.gz saved locally as {local_tar_filename}")
        return local_tar_filename


def all_messages(event) -> list[Message]:
    """All the messages in the SNS event, as Message subclasses"""
    decoder = json.decoder.JSONDecoder()
    messages_as_decoded_json = [decoder.decode(record["Sns"]["Message"]) for record in event["Records"]]
    return [Message.from_message(message) for message in messages_as_decoded_json]


# called by tests
def get_consignment_reference(message):
    return Message.from_message(message).get_consignment_reference()


def extract_lambda_versions(versions: list[dict[str, str]]) -> list[tuple[str, str]]:
    version_tuples = []
    for d in versions:
        version_tuples += list(d.items())

    return version_tuples


def update_published_documents(uri, s3_client: S3Client) -> None:
    public_bucket = PUBLIC_ASSET_BUCKET
    private_bucket = AWS_BUCKET_NAME

    response = s3_client.list_objects(Bucket=private_bucket, Prefix=uri)

    for result in response.get("Contents", []):
        key = result["Key"]

        if "parser.log" not in key and not str(key).endswith(".tar.gz"):
            source: CopySourceTypeDef = {"Bucket": private_bucket, "Key": key}
            extra_args: dict[str, Any] = {}
            s3_client.copy(source, public_bucket, key, extra_args)


def aws_clients() -> tuple[SQSClient, S3Client]:
    if os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_KEY") and os.getenv("AWS_ENDPOINT_URL"):
        session = boto3.session.Session(
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_KEY"),
        )
        sqs_client = session.client("sqs", endpoint_url=os.getenv("AWS_ENDPOINT_URL"))
        s3_client = session.client("s3", endpoint_url=os.getenv("AWS_ENDPOINT_URL"))

    else:
        session = boto3.session.Session()
        sqs_client = session.client("sqs")
        s3_client = session.client("s3")
    return sqs_client, s3_client


def process_message(message):
    """This is the core function -- take a message and ingest the referred-to contents"""

    sqs_client, s3_client = aws_clients()
    ingest = Ingest(message=message, destination_bucket=AWS_BUCKET_NAME, api_client=api_client, s3_client=s3_client)

    # Extract and parse the judgment XML
    ingest.upload_xml()
    print(f"{ingest.upload_state.title()} judgment xml for {ingest.uri}")

    ingest.send_email()

    # Store metadata in Marklogic
    has_TDR_data = "TDR" in ingest.metadata["parameters"]
    if has_TDR_data:
        ingest.store_metadata()

    # save files to S3
    ingest.save_files_to_s3()

    if ingest.will_publish():
        print(f"publishing {ingest.consignment_reference} at {ingest.uri}")
        api_client.set_published(ingest.uri, True)
        update_published_documents(ingest.uri, s3_client)
    else:
        ingest.unpublish_updated_judgment()

    print("Ingestion complete")
    return message.message


@rollbar.lambda_function
def handler(event, context):
    for message in all_messages(event):
        process_message(message)

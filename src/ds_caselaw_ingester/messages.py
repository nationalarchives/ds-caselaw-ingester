import json
import logging
import os
from abc import ABC, abstractmethod
from urllib.parse import unquote_plus

from mypy_boto3_s3.client import S3Client

from .exceptions import InvalidMessageException

logger = logging.getLogger("ingester")
logger.setLevel(logging.DEBUG)


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
        """A strange quirk: the consignment reference we receive from the V2 message is
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
        logger.info("downloading %s", s3_key)
        reference = self.get_consignment_reference()
        local_tar_filename = os.path.join("/tmp", f"{reference}.tar.gz")
        s3_client.download_file(s3_bucket, s3_key, local_tar_filename)
        if not os.path.exists(local_tar_filename):
            raise RuntimeError(f"File {local_tar_filename} not created")
        logger.info("tar.gz saved locally as %s", local_tar_filename)
        return local_tar_filename


class S3Message(V2Message):
    """An SNS message generated directly by adding a file to an S3 bucket"""

    def __init__(self, *args, **kwargs) -> None:
        self._consignment: str | None = None
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
        logger.info("downloading %s", s3_key)
        reference = self.get_consignment_reference()
        local_tar_filename = os.path.join("/tmp", f"{reference}.tar.gz")
        s3_client.download_file(s3_bucket, s3_key, local_tar_filename)
        if not os.path.exists(local_tar_filename):
            raise RuntimeError(f"File {local_tar_filename} not created")
        logger.info("tar.gz saved locally as %s", local_tar_filename)
        return local_tar_filename


def all_messages(event: dict) -> list[tuple[str | None, Message]]:
    """Parse all records in an SQS or SNS event into (message_id, Message) pairs.

    message_id is the SQS messageId (used for batch failure reporting), or None for
    direct SNS invocations.
    """
    decoder = json.decoder.JSONDecoder()
    results = []
    for record in event.get("Records", []):
        message_id = record.get("messageId")  # Present only for SQS records
        if record.get("eventSource") == "aws:sqs":
            sns_notification = decoder.decode(record["body"])
            raw = decoder.decode(sns_notification["Message"])
        else:
            raw = decoder.decode(record["Sns"]["Message"])
        results.append((message_id, Message.from_message(raw)))
    return results

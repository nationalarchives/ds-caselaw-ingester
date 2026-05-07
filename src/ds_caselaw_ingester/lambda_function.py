"""This file contains code which is used to understand an incoming message and decide what to do with it."""

import logging
import os
import tarfile

import boto3
import rollbar
from aws_lambda_powertools.utilities.typing import LambdaContext
from caselawclient.Client import (
    DEFAULT_USER_AGENT,
    MarklogicApiClient,
)
from codeguru_profiler_agent import with_lambda_profiler
from dotenv import load_dotenv

from .ingester import Ingest, LambdaContextTypedDict, perform_ingest
from .messages import Message, all_messages

logger = logging.getLogger("ingester")
logger.setLevel(logging.DEBUG)

load_dotenv()

rollbar.init(os.getenv("ROLLBAR_TOKEN"), environment=os.getenv("ROLLBAR_ENV"))
PRIVATE_ASSET_BUCKET: str = os.environ["PRIVATE_ASSET_BUCKET"]


def create_api_client():
    MARKLOGIC_HOST: str = os.environ["MARKLOGIC_HOST"]
    MARKLOGIC_USER: str = os.environ["MARKLOGIC_USER"]
    MARKLOGIC_PASSWORD: str = os.environ["MARKLOGIC_PASSWORD"]
    MARKLOGIC_USE_HTTPS: bool = bool(os.getenv("MARKLOGIC_USE_HTTPS", default=False))

    api_client = MarklogicApiClient(
        host=MARKLOGIC_HOST,
        username=MARKLOGIC_USER,
        password=MARKLOGIC_PASSWORD,
        use_https=MARKLOGIC_USE_HTTPS,
        user_agent=f"ds-caselaw-ingester/unknown {DEFAULT_USER_AGENT}",
    )
    logger.info("Initialised MarkLogic API client")

    return api_client


api_client = create_api_client()

if os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_KEY") and os.getenv("AWS_ENDPOINT_URL"):
    session = boto3.session.Session(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_KEY"),
    )
    s3_client = session.client("s3", endpoint_url=os.getenv("AWS_ENDPOINT_URL"))
else:
    session = boto3.session.Session()
    s3_client = session.client("s3")
logger.info("Initialised S3 client")


# called by tests
def get_consignment_reference(message):
    return Message.from_message(message).get_consignment_reference()


def extract_lambda_versions(versions: list[dict[str, str]]) -> list[tuple[str, str]]:
    version_tuples = []
    for d in versions:
        version_tuples += list(d.items())

    return version_tuples


@with_lambda_profiler()
@rollbar.lambda_function
def handler(event, context: LambdaContext):
    logger.info("Received event")

    batch_item_failures = []

    lambda_context: LambdaContextTypedDict = {"aws_request_id": context.aws_request_id}

    for message_id, message in all_messages(event):
        logger.info("Received messageId: %s with message: %s", message_id or "_", message.message)

        try:
            # Download the tarfile specified in the message, and inject into the ingester
            local_tar_filename = message.save_s3_response(s3_client=s3_client)
            logger.info("Tarfile saved locally as %s", local_tar_filename)
            with tarfile.open(local_tar_filename, mode="r") as tarfile_reader:
                ingest = Ingest(
                    message=message,
                    tarfile_reader=tarfile_reader,
                    destination_bucket=PRIVATE_ASSET_BUCKET,
                    destination_tar_filename=local_tar_filename,
                    api_client=api_client,
                    s3_client=s3_client,
                    lambda_context=lambda_context,
                )

                perform_ingest(ingest)
        except Exception:  # noqa: BLE001 — catch-all required for SQS partial batch failure reporting
            rollbar.report_exc_info(level="error")
            logger.exception("Error processing message")
            if message_id:
                batch_item_failures.append({"itemIdentifier": message_id})

    return {"batchItemFailures": batch_item_failures}

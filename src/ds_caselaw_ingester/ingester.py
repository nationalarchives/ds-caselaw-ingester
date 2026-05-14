"""This file contains code which is related to actually unpacking an incoming document, performing necessary manipulations, and saving it out to MarkLogic."""

import json
import logging
import os
import tarfile
from contextlib import suppress
from functools import cached_property
from typing import TYPE_CHECKING, TypedDict
from uuid import uuid4

import lxml.etree as ET
from caselawclient.Client import MarklogicApiClient
from caselawclient.client_helpers import get_document_type_class
from caselawclient.models.documents import Document, DocumentURIString
from caselawclient.models.documents.exceptions import CannotPublishUnpublishableDocument
from caselawclient.models.documents.versions import VersionAnnotation, VersionType
from caselawclient.models.identifiers import Identifier
from caselawclient.models.identifiers.neutral_citation import NeutralCitationNumber
from caselawclient.models.identifiers.press_summary_ncn import PressSummaryRelatedNCNIdentifier
from caselawclient.models.judgments import Judgment
from caselawclient.models.parser_logs import ParserLog
from caselawclient.models.press_summaries import PressSummary
from caselawclient.models.utilities.aws import S3PrefixString
from caselawclient.types import DocumentIdentifierSlug, DocumentIdentifierValue
from ds_caselaw_utils.types.metadata_schema_autogen import (
    AUTO_PUBLISH_DOCUMENT_DEFAULT,
    DocumentProcessingMetadata,
    ParserProcessMetadata,
)
from mypy_boto3_s3.client import S3Client
from notifications_python_client.notifications import NotificationsAPIClient

from .exceptions import (
    CannotPublishException,
    DocumentInsertionError,
    DocumentXMLNotYetInDatabase,
    FileNotFoundException,
    MultipleResolutionsFoundError,
)
from .file_helpers import (
    copy_file,
    extract_metadata,
    extract_source_filename,
    get_best_xml,
    modify_filename,
    store_file,
)

IDENTIFIER_CLASS_LOOKUP: dict[type[Document], type[Identifier] | None] = {
    PressSummary: PressSummaryRelatedNCNIdentifier,
    Judgment: NeutralCitationNumber,
    ParserLog: None,
}

if TYPE_CHECKING:
    from .lambda_function import Message

logger = logging.getLogger("ingester")
logger.setLevel(logging.DEBUG)

PRIVATE_ASSET_BUCKET: str = os.environ["PRIVATE_ASSET_BUCKET"]
PUBLIC_ASSET_BUCKET: str = os.environ["PUBLIC_ASSET_BUCKET"]


class SubmitterInformationDict(TypedDict):
    name: str
    email: str


class LambdaContextTypedDict(TypedDict):
    aws_request_id: str


class VersionPayloadDict(TypedDict, total=False):
    tre_raw_metadata: DocumentProcessingMetadata
    tdr_reference: str
    submitter: SubmitterInformationDict
    aws_lambda_context: LambdaContextTypedDict


def build_version_annotation_payload(
    metadata: DocumentProcessingMetadata,
    lambda_context: LambdaContextTypedDict,
) -> VersionPayloadDict:
    """Turns metadata from TRE and the Lambda context into a structured annotation payload."""
    payload: VersionPayloadDict = {"tre_raw_metadata": metadata, "aws_lambda_context": lambda_context}

    if "TDR" in metadata["parameters"]:
        payload["tdr_reference"] = metadata["parameters"]["TDR"]["Internal-Sender-Identifier"]
        payload["submitter"] = {
            "name": metadata["parameters"]["TDR"]["Contact-Name"],
            "email": metadata["parameters"]["TDR"]["Contact-Email"],
        }

    return payload


def personalise_email(uri: str, metadata: DocumentProcessingMetadata) -> dict:
    """Doesn't contain 'doctype', re-add for new judgment notification"""
    try:
        tdr_metadata = metadata["parameters"]["TDR"]
    except KeyError:
        tdr_metadata = {}

    keys = [
        "Judgment-Update",
        "Judgment-Update-Type",
        "Judgment-Update-Details",
        "Judgment-Neutral-Citation",
        "Judgment-No-Neutral-Citation",
        "Judgment-Reference",
    ]
    update_metadata = json.dumps({key: tdr_metadata.get(key) for key in keys}, indent=2)

    return {
        "url": f"{os.getenv('EDITORIAL_UI_BASE_URL')}detail?judgment_uri={uri}",
        "consignment": tdr_metadata.get("Internal-Sender-Identifier", "unknown"),
        "submitter": f"{tdr_metadata.get('Contact-Name', 'unknown')}, "
        f"{tdr_metadata.get('Source-Organization', 'unknown')}"
        f" <{tdr_metadata.get('Contact-Email', 'unknown')}>",
        "submitted_at": tdr_metadata.get("Consignment-Completed-Datetime", "unknown"),
        "update_metadata": update_metadata,
    }


class Metadata:
    def __init__(self, metadata: DocumentProcessingMetadata) -> None:
        self.metadata = metadata
        self.parameters = metadata.get("parameters", {})

    @property
    def is_tdr(self) -> bool:
        """Does the metadata say this document came from TDR?"""
        return "TDR" in self.parameters

    @property
    def trimmed_uri(self) -> DocumentURIString | None:
        """The NCN-based URI the parser believes the document should be discoverable at"""
        raw_uri = self.parameters["PARSER"].get("uri", "")
        if raw_uri:
            return DocumentURIString(raw_uri.replace("https://caselaw.nationalarchives.gov.uk/id/", ""))
        else:
            return None

    @property
    def auto_publish(self) -> bool:
        """
        Does the metadata say to automatically publish this document?
        """
        return self.parameters.get("INGESTER_OPTIONS", {}).get("auto_publish", AUTO_PUBLISH_DOCUMENT_DEFAULT)


class Ingest:
    """
    The `Ingest` object contains everything we need to know about an incoming ingestion request, including the metadata from the parser, the parsed XML, and details of the document's destination URI.

    The logic flow for determining a document's URI and if it should be inserted or updated is described in `docs/uri_logic.md`.

    :param message: The incoming message object describing where to find the document.
    :param destination_bucket: The S3 bucket to put the resultant document objects into.
    :param api_client: The API Client instance to use for this ingestion.
    :param s3_client: The S3 client instance to use for this ingestion.
    :param lambda_context: A dict containing useful information passed from the AWS Lambda context object.
    """

    def __init__(
        self,
        message: "Message",
        tarfile_reader: tarfile.TarFile,
        destination_bucket: str,
        destination_tar_filename: str,
        api_client: MarklogicApiClient,
        s3_client: S3Client,
        lambda_context: LambdaContextTypedDict,
    ) -> None:
        self.message = message
        self.destination_bucket = destination_bucket
        self.destination_tar_filename = destination_tar_filename
        self.api_client = api_client
        self.s3_client = s3_client
        self.consignment_reference: str = self.message.get_consignment_reference()
        self.document: Document | None = None

        self.aws_lambda_context = lambda_context

        logger.info("Ingester Start: Consignment reference %s", self.consignment_reference)

        self.local_tarfile_reader = tarfile_reader

        self.metadata = extract_metadata(self.local_tarfile_reader, self.consignment_reference)
        self.extracted_ncn = self.metadata["parameters"]["PARSER"].get("cite")
        self.message.update_consignment_reference(self.metadata["parameters"]["TRE"]["reference"])
        self.xml_file_name = self.metadata["parameters"]["TRE"]["payload"]["xml"]
        self.xml = get_best_xml(self.local_tarfile_reader, self.xml_file_name, self.consignment_reference)
        self.uri, self.exists_in_database = self.database_location
        logger.info("Ingesting document %s", self.uri)

    def __repr__(self):
        return f"<Ingest: {self.consignment_reference}, {self.extracted_ncn}>"

    @property
    def ingested_document_type(self) -> type[Document]:
        """Get the type of the ingested document."""
        return get_document_type_class(ET.tostring(self.xml))

    @property
    def ingested_document_type_string(self) -> str:
        """The type of the ingested document as a string, for humans"""
        return self.ingested_document_type.document_noun

    def update_document_xml(self) -> None:
        if self.metadata_object.is_tdr:
            message = "Updated document submitted by TDR user"
        else:
            message = "Updated document uploaded by Find Case Law"

        annotation = VersionAnnotation(
            VersionType.SUBMISSION,
            automated=self.metadata_object.auto_publish,
            message=message,
            payload=dict(
                build_version_annotation_payload(self.metadata, self.aws_lambda_context),
            ),  # We cast this to a dict here because VersionAnnotation doesn't yet have a TypedDict as its payload argument.
        )

        self.api_client.get_judgment_xml(self.uri, show_unpublished=True)
        self.api_client.update_document_xml(self.uri, self.xml, annotation)

    def insert_document_xml(self) -> None:
        if self.metadata_object.is_tdr:
            message = "New document submitted by TDR user"
        else:
            message = "New document uploaded by Find Case Law"
        annotation = VersionAnnotation(
            VersionType.SUBMISSION,
            automated=self.metadata_object.auto_publish,
            message=message,
            payload=dict(
                build_version_annotation_payload(self.metadata, self.aws_lambda_context),
            ),  # We cast this to a dict here because VersionAnnotation doesn't yet have a TypedDict as its payload argument.
        )
        self.api_client.insert_document_xml(
            document_uri=self.uri,
            document_xml=self.xml,
            annotation=annotation,
            document_type=self.ingested_document_type,
        )

    def set_document_identifiers(self) -> None:
        if self.document is None:
            raise DocumentXMLNotYetInDatabase("This Ingest instance has not yet been written to the database.")

        if self.document.identifiers:
            msg = f"Ingesting, but identifiers already present for {self.uri}!"
            logger.warning(msg)

        ncn = getattr(self.document, "neutral_citation", None)
        identifier_class = IDENTIFIER_CLASS_LOOKUP.get(self.ingested_document_type)

        if not identifier_class:
            return

        if ncn:
            self.document.identifiers.add(identifier_class(ncn))
            self.document.save_identifiers()
            logger.info(
                f"Ingested {self.ingested_document_type_string} had identifier {identifier_class.__name__} {ncn}",
            )
        else:
            logger.info(f"Ingested {self.ingested_document_type_string} did not have an NCN")

    def send_updated_judgment_notification(self) -> None:
        personalisation = personalise_email(self.uri, self.metadata)
        if os.getenv("ROLLBAR_ENV") != "prod":
            logger.info("Would send a notification but we're not in production.\n%s", personalisation)
            return

        notifications_client = NotificationsAPIClient(os.environ["NOTIFY_API_KEY"])
        response = notifications_client.send_email_notification(
            email_address=os.getenv("NOTIFY_EDITORIAL_ADDRESS"),
            template_id=os.getenv("NOTIFY_UPDATED_JUDGMENT_TEMPLATE_ID"),
            personalisation=personalisation,
        )
        logger.info(
            "Sent update notification to %s (Message ID: %s)",
            os.getenv("NOTIFY_EDITORIAL_ADDRESS"),
            response["id"],
        )

    def send_new_judgment_notification(self) -> None:
        personalisation = personalise_email(self.uri, self.metadata)
        personalisation["doctype"] = self.ingested_document_type_string

        if os.getenv("ROLLBAR_ENV") != "prod":
            logger.info("Would send a notification but we're not in production.\n%s", personalisation)
            return
        notifications_client = NotificationsAPIClient(os.environ["NOTIFY_API_KEY"])
        response = notifications_client.send_email_notification(
            email_address=os.getenv("NOTIFY_EDITORIAL_ADDRESS"),
            template_id=os.getenv("NOTIFY_NEW_JUDGMENT_TEMPLATE_ID"),
            personalisation=personalisation,
        )
        logger.info(
            "Sent new notification to %s (Message ID: %s)",
            os.getenv("NOTIFY_EDITORIAL_ADDRESS"),
            response["id"],
        )

    def send_bulk_judgment_notification(self) -> None:
        # Not yet implemented. We currently only autopublish judgments sent in bulk.
        pass

    def store_tdr_metadata(self, tdr_metadata) -> None:
        # Store metadata relating to the TDR process

        # Store source information
        self.api_client.set_property(
            self.uri,
            name="source-organisation",
            value=tdr_metadata["Source-Organization"],
        )
        self.api_client.set_property(self.uri, name="source-name", value=tdr_metadata["Contact-Name"])
        self.api_client.set_property(self.uri, name="source-email", value=tdr_metadata["Contact-Email"])
        # Store TDR data
        self.api_client.set_property(
            self.uri,
            name="transfer-consignment-reference",
            value=tdr_metadata["Internal-Sender-Identifier"],
        )
        self.api_client.set_property(
            self.uri,
            name="transfer-received-at",
            value=tdr_metadata["Consignment-Completed-Datetime"],
        )

    def store_parser_metadata(self, parser_metadata: ParserProcessMetadata) -> None:
        # Store metadata relating to the parsing process

        # Set parser metadata
        if "parser_run_id" in parser_metadata:
            self.api_client.set_property(
                self.uri,
                name="parser-run-id",
                value=parser_metadata["parser_run_id"],
            )

    def save_files_to_s3(self) -> None:
        # Determine if there's a word document -- we need to know before we save the tar.gz file

        source_filename = extract_source_filename(self.metadata, self.consignment_reference)
        logger.info("extracted source filename is %r", source_filename)

        # Copy original tarfile
        modified_targz_filename = (
            self.destination_tar_filename
            if source_filename
            else modify_filename(self.destination_tar_filename, "_nodocx")
        )
        with open(self.destination_tar_filename, mode="rb") as local_tar_read_buffer:
            store_file(
                file=local_tar_read_buffer,
                destination_bucket=self.destination_bucket,
                destination_folder=S3PrefixString(self.uri + "/"),
                destination_filename=os.path.basename(modified_targz_filename),
                s3_client=self.s3_client,
            )
        logger.info("saved tar.gz as %r", modified_targz_filename)

        # Store source file and rename
        # The name is None for files which have been reparsed.
        if source_filename is not None:
            source_filename_extension = source_filename.split(".")[-1].lower()  # eg. docx/pdf
            copy_file(
                self.local_tarfile_reader,
                f"{self.consignment_reference}/{source_filename}",
                self.destination_bucket,
                f"{self.uri.replace('/', '_')}.{source_filename_extension}",
                S3PrefixString(self.uri + "/"),
                self.s3_client,
            )

        # Store parser log
        with suppress(FileNotFoundException):
            copy_file(
                self.local_tarfile_reader,
                f"{self.consignment_reference}/parser.log",
                self.destination_bucket,
                "parser.log",
                S3PrefixString(self.uri + "/"),
                self.s3_client,
            )

        # Store images
        image_list = self.metadata["parameters"]["TRE"]["payload"]["images"]
        if image_list:
            for image_filename in image_list:
                copy_file(
                    self.local_tarfile_reader,
                    f"{self.consignment_reference}/{image_filename}",
                    self.destination_bucket,
                    image_filename,
                    S3PrefixString(self.uri + "/"),
                    self.s3_client,
                )

    @property
    def metadata_object(self) -> Metadata:
        return Metadata(self.metadata)

    def will_publish(self) -> bool:
        originator = self.message.originator
        # TDR
        if originator == "TDR":
            return False

        # Bulk
        if originator == "FCL S3":
            return self.metadata_object.auto_publish is True

        # reparse
        if originator == "FCL":
            if not self.exists_in_database:
                return False
            return self.api_client.get_published(self.uri) is True

        raise RuntimeError(f"Didn't recognise originator {originator!r}")

    def send_email(self) -> None:
        originator = self.message.originator
        if originator == "FCL":
            return None

        if originator == "FCL S3":
            return None if self.metadata_object.auto_publish else self.send_bulk_judgment_notification()

        if originator == "TDR":
            return (
                self.send_updated_judgment_notification()
                if self.exists_in_database
                else self.send_new_judgment_notification()
            )

        raise RuntimeError(f"Didn't recognise originator {originator!r}")

    def insert_or_update_xml(self) -> None:
        """Puts the XML into MarkLogic, either by updating an existing document (if `self.exists_in_database`) or by creating a new one."""
        if self.exists_in_database:
            try:
                self.update_document_xml()
            except Exception as err:
                raise DocumentInsertionError(
                    f"Updating {self.ingested_document_type_string} {self.uri} failed. Consignment Ref: {self.consignment_reference}",
                ) from err
        else:
            try:
                self.insert_document_xml()
            except Exception as err:
                raise DocumentInsertionError(
                    f"Inserting {self.ingested_document_type_string} {self.uri} failed. Consignment Ref: {self.consignment_reference}",
                ) from err

        # This is the only place we should be setting self.document, once the XML is in the database
        # get_document_by_uri will raise an exception if the expected document doesn't exist
        self.document = self.api_client.get_document_by_uri(DocumentURIString(self.uri))

    @cached_property
    def find_existing_document_by_ncn(self) -> DocumentURIString | None:
        """
        Is there an existing document claiming to be this one? (i.e. NCN and type match)
        Return the MarklogicURI of that document.
        """
        if not self.extracted_ncn:
            return None

        raw_resolutions = self.api_client.resolve_from_identifier_value(
            DocumentIdentifierValue(self.extracted_ncn),
            published_only=False,
        )
        identifier_type = IDENTIFIER_CLASS_LOOKUP[self.ingested_document_type]
        resolutions = [resolution for resolution in raw_resolutions if resolution.identifier_type == identifier_type]

        if len(resolutions) == 1:
            return resolutions[0].document_uri.as_document_uri()

        if len(resolutions) > 1:
            raise MultipleResolutionsFoundError(f"Multiple resolutions for {self.uri} already, before ingest!")

        return None

    @property
    def upload_state(self) -> str:
        return "updated" if self.exists_in_database else "inserted"

    @cached_property
    def database_location(self) -> tuple[DocumentURIString, bool]:
        """Returns the chosen database location for the ingested document, and
        whether a document already exists at that location"""

        # Is a URI present in the parser metadata?
        if trimmed_uri := self.metadata_object.trimmed_uri:  # noqa: SIM102
            # Is there a document in MarkLogic at that URL?
            if slug_resolutions := self.api_client.resolve_from_identifier_slug(DocumentIdentifierSlug(trimmed_uri)):
                if len(slug_resolutions) > 1:
                    msg = f"uri: {trimmed_uri}"
                    raise MultipleResolutionsFoundError(msg)
                # Set URI of the document being ingested to the URI of the one it is replacing in MarkLogic
                return (slug_resolutions[0].document_uri.as_document_uri(), True)

        # Is there an existing document in MarkLogic with that NCN in the relevant identifier scheme?
        if self.find_existing_document_by_ncn:
            # set document URI to URI of existing document
            return (self.find_existing_document_by_ncn, True)

        # Generate new UUID-based URI
        doc_uuid = DocumentURIString("d-" + str(uuid4()))
        return (doc_uuid, False)


def perform_ingest(ingest: Ingest) -> None:
    """Given an Ingest object, perform the necessary tasks to put it in MarkLogic and tell people about it."""

    # Extract and parse the judgment XML
    ingest.insert_or_update_xml()

    if not ingest.document:
        raise DocumentInsertionError("Document not present in MarkLogic after attempting insert or update.")

    logger.info("%s judgment xml for %s", ingest.upload_state.title(), ingest.uri)
    ingest.set_document_identifiers()

    ingest.send_email()

    if "TDR" in ingest.metadata["parameters"]:
        ingest.store_tdr_metadata(ingest.metadata["parameters"]["TDR"])

    if "PARSER" in ingest.metadata["parameters"]:
        ingest.store_parser_metadata(ingest.metadata["parameters"]["PARSER"])

    # save files to S3
    ingest.save_files_to_s3()

    if ingest.will_publish():
        try:
            logger.info("publishing %s at %s", ingest.consignment_reference, ingest.uri)
            ingest.document.publish()
        except CannotPublishUnpublishableDocument as err:
            raise CannotPublishException(*err.args) from err
    else:
        logger.info("unpublishing %s", ingest.uri)
        ingest.document.unpublish()

    logger.info("Ingestion complete")

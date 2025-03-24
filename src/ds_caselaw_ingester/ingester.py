"""This file contains code which is related to actually unpacking an incoming document, performing necessary manipulations, and saving it out to MarkLogic."""

import json
import logging
import os
import tarfile
import xml
import xml.etree.ElementTree as ET
from contextlib import suppress
from functools import cached_property
from typing import IO, TYPE_CHECKING, Any, Optional, TypedDict
from uuid import uuid4
from xml.sax.saxutils import escape

from botocore.exceptions import NoCredentialsError
from caselawclient.Client import MarklogicApiClient, MarklogicResourceNotFoundError
from caselawclient.client_helpers import VersionAnnotation, VersionType, get_document_type_class
from caselawclient.models.documents import Document, DocumentURIString
from caselawclient.models.documents.body import DocumentBody
from caselawclient.models.identifiers import Identifier
from caselawclient.models.identifiers.neutral_citation import NeutralCitationNumber
from caselawclient.models.identifiers.press_summary_ncn import PressSummaryRelatedNCNIdentifier
from caselawclient.models.judgments import Judgment
from caselawclient.models.parser_logs import ParserLog
from caselawclient.models.press_summaries import PressSummary
from caselawclient.models.utilities.aws import S3PrefixString
from caselawclient.types import DocumentIdentifierValue
from mypy_boto3_s3.client import S3Client
from mypy_boto3_s3.type_defs import CopySourceTypeDef
from notifications_python_client.notifications import NotificationsAPIClient

from .exceptions import (
    DocumentInsertionError,
    DocxFilenameNotFoundException,
    FileNotFoundException,
)


class MultipleResolutionsFoundError(DocumentInsertionError):
    pass


IDENTIFIER_CLASS_LOOKUP: dict[type[Document], Optional[type[Identifier]]] = {
    PressSummary: PressSummaryRelatedNCNIdentifier,
    Judgment: NeutralCitationNumber,
    ParserLog: None,
}

if TYPE_CHECKING:
    from .lambda_function import Message

logger = logging.getLogger("ingester")
logger.setLevel(logging.DEBUG)

AWS_BUCKET_NAME: str = os.environ["AWS_BUCKET_NAME"]
PUBLIC_ASSET_BUCKET: str = os.environ["PUBLIC_ASSET_BUCKET"]


class TREMetadataDict(TypedDict):
    parameters: dict[str, Any]


class SubmitterInformationDict(TypedDict):
    name: str
    email: str


class VersionPayloadDict(TypedDict, total=False):
    tre_raw_metadata: TREMetadataDict
    tdr_reference: str
    submitter: SubmitterInformationDict


def extract_metadata(tar: tarfile.TarFile, consignment_reference: str) -> TREMetadataDict:
    te_metadata_file = None
    decoder = json.decoder.JSONDecoder()
    for member in tar.getmembers():
        if "-metadata.json" in member.name:
            te_metadata_file = tar.extractfile(member)

    if te_metadata_file is None:
        raise FileNotFoundException(f"Metadata file not found. Consignment Ref: {consignment_reference}")
    return decoder.decode(te_metadata_file.read().decode("utf-8"))


def copy_file(
    tarfile: tarfile.TarFile,
    input_filename: str,
    output_bucket: str,
    output_filename: str,
    output_location: S3PrefixString,
    s3_client: S3Client,
) -> None:
    """Copy the specified file from the input tar to the destination location."""
    try:
        file = tarfile.extractfile(input_filename)
        store_file(
            file=file,
            destination_bucket=output_bucket,
            destination_folder=output_location,
            destination_filename=output_filename,
            s3_client=s3_client,
        )
    except KeyError as err:
        raise FileNotFoundException(f"File was not found: {input_filename}, files were {tarfile.getnames()} ") from err


def store_file(
    file,
    destination_bucket: str,
    destination_folder: S3PrefixString,
    destination_filename: str,
    s3_client: S3Client,
):
    """Given a file, store it in the specified location in S3."""
    pathname: str = destination_folder + destination_filename
    try:
        s3_client.upload_fileobj(file, destination_bucket, pathname)
        print(f"Upload Successful {pathname}")
    except FileNotFoundError:
        print(f"The file {pathname} was not found")
    except NoCredentialsError:
        print("Credentials not available")


def extract_xml_file(tar: tarfile.TarFile, xml_file_name: str) -> Optional[IO[bytes]]:
    xml_file = None
    if xml_file_name:
        for member in tar.getmembers():
            if xml_file_name in member.name:
                xml_file = tar.extractfile(member)
    return xml_file


def parse_xml(xml: bytes) -> ET.Element:
    ET.register_namespace("", "http://docs.oasis-open.org/legaldocml/ns/akn/3.0")
    ET.register_namespace("uk", "https://caselaw.nationalarchives.gov.uk/akn")
    return ET.XML(xml)


def create_parser_log_xml(tar: tarfile.TarFile) -> bytes:
    parser_log_value = "<error>parser.log not found</error>"
    for member in tar.getmembers():
        if "parser.log" in member.name:
            parser_log = tar.extractfile(member)
            if parser_log is not None:
                parser_log_contents = escape(parser_log.read().decode("utf-8"))
            else:
                parser_log_contents = "Unable to read parser log file!"
            parser_log_value = f"<error>{parser_log_contents}</error>"
    return parser_log_value.encode("utf-8")


def get_best_xml(tar: tarfile.TarFile, xml_file_name: str, consignment_reference: str) -> ET.Element:
    xml_file = extract_xml_file(tar, xml_file_name)
    if xml_file:
        contents = xml_file.read()
        try:
            return parse_xml(contents)
        except ET.ParseError:
            print(
                f"Invalid XML file for consignment reference: {consignment_reference}."
                f" Falling back to parser.log contents.",
            )
            contents = create_parser_log_xml(tar)
            return parse_xml(contents)
    else:
        print(
            f"No XML file found in tarfile."
            f"consignment reference: {consignment_reference}."
            f" Falling back to parser.log contents.",
        )
        contents = create_parser_log_xml(tar)
        return parse_xml(contents)


def _build_version_annotation_payload_from_metadata(metadata: TREMetadataDict) -> VersionPayloadDict:
    """Turns metadata from TRE into a structured annotation payload."""
    payload: VersionPayloadDict = {
        "tre_raw_metadata": metadata,
    }

    if "TDR" in metadata["parameters"]:
        payload["tdr_reference"] = metadata["parameters"]["TDR"]["Internal-Sender-Identifier"]
        payload["submitter"] = {
            "name": metadata["parameters"]["TDR"]["Contact-Name"],
            "email": metadata["parameters"]["TDR"]["Contact-Email"],
        }

    return payload


def personalise_email(uri: str, metadata: TREMetadataDict) -> dict:
    """Doesn't contain 'doctype', re-add for new judgment notification"""
    try:
        tdr_metadata = metadata["parameters"]["TDR"]
    except KeyError:
        tdr_metadata = {}
    return {
        "url": f"{os.getenv('EDITORIAL_UI_BASE_URL')}detail?judgment_uri={uri}",
        "consignment": tdr_metadata.get("Internal-Sender-Identifier", "unknown"),
        "submitter": f"{tdr_metadata.get('Contact-Name', 'unknown')}, "
        f"{tdr_metadata.get('Source-Organization', 'unknown')}"
        f" <{tdr_metadata.get('Contact-Email', 'unknown')}>",
        "submitted_at": tdr_metadata.get("Consignment-Completed-Datetime", "unknown"),
    }


def extract_docx_filename(metadata: TREMetadataDict, consignment_reference: str) -> str:
    try:
        return metadata["parameters"]["TRE"]["payload"]["filename"]
    except KeyError as err:
        raise DocxFilenameNotFoundException(
            f"No .docx filename was found in metadata. Consignment Ref: {consignment_reference}, metadata: {metadata}",
        ) from err


def modify_filename(original: str, addition: str) -> str:
    "Add an addition after the filename, so TRE-2024-A.tar.gz becomes TRE-2024-A_nodocx.tar.gz"
    path, basename = os.path.split(original)
    # dot will be an empty string if there is no dot in the filename.
    # prefix will be everything upto and not including the first dot.
    prefix, dot, suffix = basename.partition(".")
    new_basename = f"{prefix}{addition}{dot}{suffix}"
    return os.path.join(path, new_basename)


def extract_document_uri_from_metadata(
    metadata: TREMetadataDict,
    consignment_reference: str,
) -> Optional[DocumentURIString]:
    """TODO: Remove this function once we're back to UUID-based URIs."""
    uri = metadata["parameters"]["PARSER"].get("uri", "")

    if uri:
        return DocumentURIString(uri.replace("https://caselaw.nationalarchives.gov.uk/id/", ""))
    else:
        return None


class Metadata:
    def __init__(self, metadata: TREMetadataDict) -> None:
        self.metadata = metadata
        self.parameters = metadata.get("parameters", {})

    @property
    def is_tdr(self) -> bool:
        """Does the metadata say this document came from TDR?"""
        return "TDR" in self.parameters

    @property
    def force_publish(self) -> bool:
        """
        Does the metadata say to automatically publish this document?
        """
        return self.parameters.get("INGESTER_OPTIONS", {}).get("auto_publish", False)


class Ingest:
    def __init__(
        self,
        message: "Message",
        destination_bucket: str,
        api_client: MarklogicApiClient,
        s3_client: S3Client,
    ) -> None:
        self.message = message
        self.destination_bucket = destination_bucket
        self.api_client = api_client
        self.s3_client = s3_client
        self.inserted: bool = False
        self.updated: bool = False
        self.consignment_reference: str = self.message.get_consignment_reference()
        print(f"Ingester Start: Consignment reference {self.consignment_reference}")
        print(f"Received Message: {self.message.message}")
        self.local_tar_filename = self.save_tar_file_in_s3()

        with tarfile.open(self.local_tar_filename, mode="r") as tar:
            self.metadata = extract_metadata(tar, self.consignment_reference)
            self.extracted_ncn = self.metadata["parameters"]["PARSER"].get("cite")
            self.message.update_consignment_reference(self.metadata["parameters"]["TRE"]["reference"])
            self.xml_file_name = self.metadata["parameters"]["TRE"]["payload"]["xml"]
            self.xml = get_best_xml(tar, self.xml_file_name, self.consignment_reference)
            self.uri = self.determine_uri()
            self.body = DocumentBody(xml.etree.ElementTree.tostring(self.xml))  # not needed?
            print(f"Ingesting document {self.uri}")

    def determine_uri(self) -> DocumentURIString:
        # TODO: remove `metadata_uri` once we reinstate UUIDs
        metadata_uri = extract_document_uri_from_metadata(
            metadata=self.metadata,
            consignment_reference=self.consignment_reference,
        )
        if self.existing_document_uri:
            return self.existing_document_uri
        if metadata_uri:
            return metadata_uri
        return DocumentURIString("d-" + str(uuid4()))

    def save_tar_file_in_s3(self) -> str:
        """This should be mocked out for testing -- get the tar file from S3 and
        save locally, returning the filename it was saved at"""
        return self.message.save_s3_response(self.s3_client)

    @property
    def ingested_document_type(self) -> type[Document]:
        """Get the type of the ingested document."""
        return get_document_type_class(ET.tostring(self.xml))

    @property
    def ingested_document_type_string(self) -> str:
        """The type of the ingested document as a string, for humans"""
        return self.ingested_document_type.document_noun

    def update_document_xml(self) -> bool:
        if self.metadata_object.is_tdr:
            message = "Updated document submitted by TDR user"
        else:
            message = "Updated document uploaded by Find Case Law"
        try:
            annotation = VersionAnnotation(
                VersionType.SUBMISSION,
                automated=self.metadata_object.force_publish,
                message=message,
                payload=dict(
                    _build_version_annotation_payload_from_metadata(self.metadata),
                ),  # We cast this to a dict here because VersionAnnotation doesn't yet have a TypedDict as its payload argument.
            )

            self.api_client.get_judgment_xml(self.uri, show_unpublished=True)
            self.api_client.update_document_xml(self.uri, self.xml, annotation)
            return True
        except MarklogicResourceNotFoundError:
            return False

    def insert_document_xml(self) -> bool:
        if self.metadata_object.is_tdr:
            message = "New document submitted by TDR user"
        else:
            message = "New document uploaded by Find Case Law"
        annotation = VersionAnnotation(
            VersionType.SUBMISSION,
            automated=self.metadata_object.force_publish,
            message=message,
            payload=dict(
                _build_version_annotation_payload_from_metadata(self.metadata),
            ),  # We cast this to a dict here because VersionAnnotation doesn't yet have a TypedDict as its payload argument.
        )
        self.api_client.insert_document_xml(
            document_uri=self.uri,
            document_xml=self.xml,
            annotation=annotation,
            document_type=self.ingested_document_type,
        )
        return True

    def set_document_identifiers(self) -> None:
        doc = self.api_client.get_document_by_uri(DocumentURIString(self.uri))
        if doc.identifiers:
            msg = f"Ingesting, but identifiers already present for {self.uri}!"
            logger.warning(msg)

        ncn = getattr(doc, "neutral_citation", None)
        identifier_class = IDENTIFIER_CLASS_LOOKUP.get(self.ingested_document_type, None)

        if not identifier_class:
            return

        if ncn:
            doc.identifiers.add(identifier_class(ncn))
            doc.save_identifiers()
            logger.info(
                f"Ingested {self.ingested_document_type_string} had identifier {identifier_class.__name__} {ncn}",
            )
        else:
            logger.info(f"Ingested {self.ingested_document_type_string} did not have an NCN")

    def send_updated_judgment_notification(self) -> None:
        personalisation = personalise_email(self.uri, self.metadata)
        if os.getenv("ROLLBAR_ENV") != "prod":
            print(f"Would send a notification but we're not in production.\n{personalisation}")
            return

        notifications_client = NotificationsAPIClient(os.environ["NOTIFY_API_KEY"])
        response = notifications_client.send_email_notification(
            email_address=os.getenv("NOTIFY_EDITORIAL_ADDRESS"),
            template_id=os.getenv("NOTIFY_UPDATED_JUDGMENT_TEMPLATE_ID"),
            personalisation=personalisation,
        )
        print(f"Sent update notification to {os.getenv('NOTIFY_EDITORIAL_ADDRESS')} (Message ID: {response['id']})")

    def send_new_judgment_notification(self) -> None:
        personalisation = personalise_email(self.uri, self.metadata)
        personalisation["doctype"] = self.ingested_document_type_string

        if os.getenv("ROLLBAR_ENV") != "prod":
            print(f"Would send a notification but we're not in production.\n{personalisation}")
            return
        notifications_client = NotificationsAPIClient(os.environ["NOTIFY_API_KEY"])
        response = notifications_client.send_email_notification(
            email_address=os.getenv("NOTIFY_EDITORIAL_ADDRESS"),
            template_id=os.getenv("NOTIFY_NEW_JUDGMENT_TEMPLATE_ID"),
            personalisation=personalisation,
        )
        print(f"Sent new notification to {os.getenv('NOTIFY_EDITORIAL_ADDRESS')} (Message ID: {response['id']})")

    def send_bulk_judgment_notification(self) -> None:
        # Not yet implemented. We currently only autopublish judgments sent in bulk.
        pass

    def unpublish_updated_judgment(self) -> None:
        document = Document(self.uri, self.api_client)
        document.unpublish()

    def store_metadata(self) -> None:
        tdr_metadata = self.metadata["parameters"]["TDR"]

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

    def save_files_to_s3(self) -> None:
        # Determine if there's a word document -- we need to know before we save the tar.gz file
        docx_filename = extract_docx_filename(self.metadata, self.consignment_reference)
        print(f"extracted docx filename is {docx_filename!r}")

        # Copy original tarfile
        modified_targz_filename = (
            self.local_tar_filename if docx_filename else modify_filename(self.local_tar_filename, "_nodocx")
        )
        with open(self.local_tar_filename, mode="rb") as local_tar:
            store_file(
                file=local_tar,
                destination_bucket=self.destination_bucket,
                destination_folder=S3PrefixString(self.uri + "/"),
                destination_filename=os.path.basename(modified_targz_filename),
                s3_client=self.s3_client,
            )
        print(f"saved tar.gz as {modified_targz_filename!r}")

        # Store docx and rename
        # The docx_filename is None for files which have been reparsed.
        if docx_filename is not None:
            with tarfile.open(self.local_tar_filename, mode="r") as tar:
                copy_file(
                    tar,
                    f"{self.consignment_reference}/{docx_filename}",
                    self.destination_bucket,
                    f"{self.uri.replace('/', '_')}.docx",
                    S3PrefixString(self.uri + "/"),
                    self.s3_client,
                )

        # Store parser log
        with suppress(FileNotFoundException), tarfile.open(self.local_tar_filename, mode="r") as tar:
            copy_file(
                tar,
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
                with tarfile.open(self.local_tar_filename, mode="r") as tar:
                    copy_file(
                        tar,
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
            return self.metadata_object.force_publish is True

        # reparse
        if originator == "FCL":
            if not self.existing_document_uri:
                return False
            return self.api_client.get_published(self.existing_document_uri) is True

        raise RuntimeError(f"Didn't recognise originator {originator!r}")

    def publish(self) -> None:
        document = Document(self.uri, self.api_client)
        document.publish()

    def send_email(self) -> None:
        originator = self.message.originator
        if originator == "FCL":
            return None

        if originator == "FCL S3":
            return None if self.metadata_object.force_publish else self.send_bulk_judgment_notification()

        if originator == "TDR":
            return self.send_new_judgment_notification() if self.inserted else self.send_updated_judgment_notification()

        raise RuntimeError(f"Didn't recognise originator {originator!r}")

    def upload_xml(self) -> None:
        ## Find documents of same type with the same NCN
        # TODO DRAGON

        if self.existing_document_uri:
            self.updated = self.update_document_xml()
            if not self.updated:
                raise DocumentInsertionError(
                    f"Updating {self.existing_document_uri} failed. Consignment Ref: {self.consignment_reference}",
                )
        else:
            self.inserted = self.insert_document_xml()
            if not self.inserted:
                raise DocumentInsertionError(
                    f"Inserting XXX TODO XXX {self.uri} failed. Consignment Ref: {self.consignment_reference}",
                )

    @cached_property
    def existing_document_uri(self) -> Optional[DocumentURIString]:
        """
        Is there an existing document claiming to be this one? (i.e. NCN and type match)
        Return the MarklogicURI of that document.
        """
        raw_resolutions = self.api_client.resolve_from_identifier_value(DocumentIdentifierValue(self.extracted_ncn))
        identifier_type = IDENTIFIER_CLASS_LOOKUP[self.ingested_document_type]
        resolutions = [resolution for resolution in raw_resolutions if resolution.identifier_type == identifier_type]

        if len(resolutions) == 1:
            return resolutions[0].document_uri.as_document_uri()

        if len(resolutions) > 1:
            raise MultipleResolutionsFoundError(f"Multiple resolutions for {self.uri} already, before ingest!")

        return None

    @property
    def upload_state(self) -> str:
        return "updated" if self.updated else "inserted"

    def update_published_documents(self, public_bucket: str) -> None:
        """Copy all assets (except .tar.gz and parser.log) from the private bucket which have the prefix of this document's URI to the public bucket."""
        private_bucket = AWS_BUCKET_NAME

        response = self.s3_client.list_objects(Bucket=private_bucket, Prefix=self.uri)

        for result in response.get("Contents", []):
            key = result["Key"]

            if "parser.log" not in key and not str(key).endswith(".tar.gz"):
                source: CopySourceTypeDef = {"Bucket": private_bucket, "Key": key}
                extra_args: dict[str, Any] = {}
                print(f"copying {private_bucket} / {key} to {public_bucket} / {key}")
                self.s3_client.copy(source, public_bucket, key, extra_args)


def perform_ingest(ingest: Ingest) -> None:
    """Given an Ingest object, perform the necessary tasks to put it in MarkLogic and tell people about it."""

    # Extract and parse the judgment XML
    ingest.upload_xml()
    print(f"{ingest.upload_state.title()} judgment xml for {ingest.uri}")
    ingest.set_document_identifiers()

    ingest.send_email()

    # Store metadata in Marklogic
    has_TDR_data = "TDR" in ingest.metadata["parameters"]
    if has_TDR_data:
        ingest.store_metadata()

    # save files to S3
    ingest.save_files_to_s3()

    if ingest.will_publish():
        print(f"publishing {ingest.consignment_reference} at {ingest.uri}")
        ingest.publish()
        ingest.update_published_documents(PUBLIC_ASSET_BUCKET)
    else:
        ingest.unpublish_updated_judgment()

    print("Ingestion complete")

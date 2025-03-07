"""This file contains code which is related to actually unpacking an incoming document, performing necessary manipulations, and saving it out to MarkLogic."""

import json
import logging
import os
import tarfile
import xml.etree.ElementTree as ET
from contextlib import suppress
from typing import IO, TYPE_CHECKING, Any, Optional, TypedDict
from uuid import uuid4
from xml.sax.saxutils import escape

from botocore.exceptions import NoCredentialsError
from caselawclient.Client import MarklogicApiClient, MarklogicResourceNotFoundError
from caselawclient.client_helpers import VersionAnnotation, VersionType, get_document_type_class
from caselawclient.models.documents import Document, DocumentURIString
from caselawclient.models.identifiers.neutral_citation import NeutralCitationNumber
from caselawclient.models.identifiers.press_summary_ncn import PressSummaryRelatedNCNIdentifier
from caselawclient.models.press_summaries import PressSummary
from caselawclient.models.utilities.aws import S3PrefixString
from mypy_boto3_s3.client import S3Client
from notifications_python_client.notifications import NotificationsAPIClient

from .exceptions import (
    DocumentInsertionError,
    FileNotFoundException,
)

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


def get_best_xml(uri, tar: tarfile.TarFile, xml_file_name: str, consignment_reference: str) -> ET.Element:
    xml_file = extract_xml_file(tar, xml_file_name)
    if xml_file:
        contents = xml_file.read()
        try:
            return parse_xml(contents)
        except ET.ParseError:
            print(
                f"Invalid XML file for uri: {uri}, consignment reference: {consignment_reference}."
                f" Falling back to parser.log contents.",
            )
            contents = create_parser_log_xml(tar)
            return parse_xml(contents)
    else:
        print(
            f"No XML file found in tarfile for uri: {uri}, filename: {xml_file_name},"
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

    tdr_metadata = metadata.get("parameters", {}).get("TDR")

    if tdr_metadata:
        payload["tdr_reference"] = tdr_metadata["Internal-Sender-Identifier"]
        payload["submitter"] = {
            "name": tdr_metadata["Contact-Name"],
            "email": tdr_metadata["Contact-Email"],
        }

    return payload


def personalise_email(uri: str, tdr_metadata) -> dict:
    """Doesn't contain 'doctype', re-add for new judgment notification"""
    return {
        "url": f"{os.getenv('EDITORIAL_UI_BASE_URL')}detail?judgment_uri={uri}",
        "consignment": tdr_metadata.get("Internal-Sender-Identifier", "unknown"),
        "submitter": f"{tdr_metadata.get('Contact-Name', 'unknown')}, "
        f"{tdr_metadata.get('Source-Organization', 'unknown')}"
        f" <{tdr_metadata.get('Contact-Email', 'unknown')}>",
        "submitted_at": tdr_metadata.get("Consignment-Completed-Datetime", "unknown"),
    }


def modify_filename(original: str, addition: str) -> str:
    "Add an addition after the filename, so TRE-2024-A.tar.gz becomes TRE-2024-A_nodocx.tar.gz"
    path, basename = os.path.split(original)
    # dot will be an empty string if there is no dot in the filename.
    # prefix will be everything upto and not including the first dot.
    prefix, dot, suffix = basename.partition(".")
    new_basename = f"{prefix}{addition}{dot}{suffix}"
    return os.path.join(path, new_basename)


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


class MarklogicIngester:
    def __init__(
        self,
        message: "Message",
        xml: ET.Element,
        uri: DocumentURIString,
        metadata: TREMetadataDict,
        api_client: MarklogicApiClient,
    ) -> None:
        self.message = message
        self.xml = xml
        self.uri = uri
        self.metadata = metadata
        self.api_client = api_client

    def store_data(self) -> bool:
        inserted = self.upload_xml()
        # Store metadata in Marklogic
        has_tdr_metadata = "TDR" in self.metadata_object.parameters
        if has_tdr_metadata:
            self.store_metadata()
        return inserted

    @property
    def ingested_document_type(self) -> type[Document]:
        """Get the type of the ingested document."""
        return get_document_type_class(ET.tostring(self.xml))

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

        ncn = doc.neutral_citation
        identifier_class = PressSummaryRelatedNCNIdentifier if isinstance(doc, PressSummary) else NeutralCitationNumber

        if ncn:
            doc.identifiers.add(identifier_class(ncn))
            doc.save_identifiers()
            logger.info(f"Ingested document had identifier {identifier_class.__name__} {ncn}")
        else:
            logger.info("Ingested document had NCN (NOT FOUND)")

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

    @property
    def metadata_object(self) -> Metadata:
        return Metadata(self.metadata)

    def upload_xml(self) -> bool:
        self.updated = self.update_document_xml()
        inserted = False if self.updated else self.insert_document_xml()
        if not self.updated and not inserted:
            raise DocumentInsertionError(
                f"Judgment {self.uri} failed to insert into Marklogic.",
            )
        self.set_document_identifiers()
        print(f"{self.upload_state.title()} judgment xml for {self.uri}")
        return inserted

    @property
    def upload_state(self) -> str:
        return "updated" if self.updated else "inserted"


class S3Ingester:
    def __init__(
        self,
        uri: DocumentURIString,
        docx_filename: str,
        consignment_reference: str,
        image_list: list[str],
        local_tar_filename: str,
        destination_bucket: str,
        s3_client: S3Client,
    ) -> None:
        self.uri = uri
        self.docx_filename = docx_filename
        self.consignment_reference = consignment_reference
        self.image_list = image_list
        self.local_tar_filename = local_tar_filename
        self.destination_bucket = destination_bucket
        self.s3_client = s3_client

    def save_files_to_unpublished_bucket(self) -> None:
        # Determine if there's a word document -- we need to know before we save the tar.gz file
        # Copy original tarfile
        modified_targz_filename = (
            self.local_tar_filename if self.docx_filename else modify_filename(self.local_tar_filename, "_nodocx")
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
        if self.docx_filename is not None:
            with tarfile.open(self.local_tar_filename, mode="r") as tar:
                copy_file(
                    tar,
                    f"{self.consignment_reference}/{self.docx_filename}",
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
        if self.image_list:
            for image_filename in self.image_list:
                with tarfile.open(self.local_tar_filename, mode="r") as tar:
                    copy_file(
                        tar,
                        f"{self.consignment_reference}/{image_filename}",
                        self.destination_bucket,
                        image_filename,
                        S3PrefixString(self.uri + "/"),
                        self.s3_client,
                    )


class IngesterNotifer:
    def __init__(self, uri, originator, inserted, force_publish, tdr_metadata):
        self.uri = uri
        self.originator = originator
        self.inserted = inserted
        self.force_publish = force_publish
        self.tdr_metadata = tdr_metadata

    def send_email(self) -> None:
        originator = self.originator
        if originator == "FCL":
            return None

        if originator == "FCL S3":
            return None if self.force_publish else self._send_bulk_judgment_notification()

        if originator == "TDR":
            return (
                self._send_new_judgment_notification() if self.inserted else self._send_updated_judgment_notification()
            )

        raise RuntimeError(f"Didn't recognise originator {originator!r}")

    def _send_new_judgment_notification(self) -> None:
        doctype = "Press Summary" if "/press-summary/" in self.uri else "Judgment"

        personalisation = personalise_email(self.uri, self.tdr_metadata)
        personalisation["doctype"] = doctype

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

    def _send_bulk_judgment_notification(self) -> None:
        # Not yet implemented. We currently only autopublish judgments sent in bulk.
        pass

    def _send_updated_judgment_notification(self) -> None:
        personalisation = personalise_email(self.uri, self.tdr_metadata)
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


class IngesterPublisher:
    def __init__(self, document: Document, originator: str, force_publish: bool = False):
        self.document = document
        self.originator = originator
        self.force_publish = force_publish

    def process(self):
        if self.will_publish():
            print(f"publishing {self.document.consignment_reference} at {self.document.uri}")
            self.document.publish()
        else:
            self.document.unpublish()

    def will_publish(self) -> bool:
        # TDR
        if self.originator == "TDR":
            return False

        # Bulk
        if self.originator == "FCL S3":
            return self.force_publish is True

        # reparse
        if self.originator == "FCL":
            return self.document.api_client.get_published(self.document.uri) is True

        raise RuntimeError(f"Didn't recognise originator {self.originator!r}")


def process_message(
    message: "Message",
    destination_bucket: str,
    s3_client: S3Client,
    api_client: MarklogicApiClient,
) -> None:
    print(f"Received Message: {message.message}")

    # Extract consignment reference
    consignment_reference: str = message.get_consignment_reference()

    if consignment_reference:
        print(f"Ingester Start: Consignment reference {consignment_reference}")
    else:
        print("Ingester Start: Consignment reference not available in message")

    # Build Document URI
    uri = DocumentURIString("d-" + str(uuid4()))
    print(f"Ingesting document {uri}")

    # Save tar.gz file locally
    local_tar_filename = message.save_s3_response(s3_client)

    # Extract metadata and XML
    with tarfile.open(local_tar_filename, mode="r") as tar:
        metadata = extract_metadata(tar, consignment_reference)
        metadata_parameters = metadata["parameters"]
        tdr_metadata = metadata_parameters.get("TDR", {})
        tre_metadata = metadata_parameters.get("TRE", {})
        tre_metadata_payload = tre_metadata["payload"]
        xml_file_name = tre_metadata_payload["xml"]
        xml = get_best_xml(uri, tar, xml_file_name, consignment_reference)

    # Update consignment reference in message with reference passed in metadata
    # This is a strange quirk: the consignment reference is not available in the message
    # when it orginates from the S3 bucket, but in this scenario we can extract an equivalent
    # reference from the metadata in the s3 bucket itself.
    tre_consignment_reference = tre_metadata["reference"]
    message.update_consignment_reference(tre_consignment_reference)

    # Store data in Marklogic
    marklogic_ingester = MarklogicIngester(
        message=message,
        xml=xml,
        uri=uri,
        metadata=metadata,
        api_client=api_client,
    )
    inserted = marklogic_ingester.store_data()

    docx_filename = tre_metadata["filename"]
    print(f"extracted docx filename is {docx_filename!r}")

    image_list = tre_metadata_payload["images"]

    # Save files to unpublished s3 bucket
    s3_ingester = S3Ingester(
        uri=uri,
        docx_filename=docx_filename,
        consignment_reference=message.get_consignment_reference(),
        image_list=image_list,
        local_tar_filename=local_tar_filename,
        destination_bucket=destination_bucket,
        s3_client=s3_client,
    )
    s3_ingester.save_files_to_unpublished_bucket()

    originator = message.originator
    metadata_object = Metadata(metadata)
    force_publish = metadata_object.force_publish

    # publish or unpublish the document
    document = Document(uri, api_client)
    ingester_publisher = IngesterPublisher(document, originator, force_publish)
    ingester_publisher.process()

    # send email notification
    ingester_notifier = IngesterNotifer(uri, originator, inserted, force_publish, tdr_metadata)
    ingester_notifier.send_email()

    print("Ingestion complete")

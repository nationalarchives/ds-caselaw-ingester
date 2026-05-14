import json
import logging
import os
import tarfile
from typing import IO
from xml.sax.saxutils import escape

import lxml.etree as ET
from botocore.exceptions import NoCredentialsError
from caselawclient.models.utilities.aws import S3PrefixString
from caselawclient.xml_helpers import Element
from ds_caselaw_utils.types.metadata_schema_autogen import DocumentProcessingMetadata
from mypy_boto3_s3.client import S3Client

from .exceptions import (
    DocxFilenameNotFoundException,
    FileNotFoundException,
)

logger = logging.getLogger("ingester")
logger.setLevel(logging.DEBUG)


def extract_metadata(tar: tarfile.TarFile, consignment_reference: str) -> DocumentProcessingMetadata:
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
        logger.info("Upload Successful %s", pathname)
    except FileNotFoundError:
        logger.error("The file %s was not found", pathname)
    except NoCredentialsError:
        logger.error("Credentials not available")


def extract_xml_file(tar: tarfile.TarFile, xml_file_name: str) -> IO[bytes] | None:
    xml_file = None
    if xml_file_name:
        for member in tar.getmembers():
            if xml_file_name in member.name:
                xml_file = tar.extractfile(member)
    return xml_file


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


def get_best_xml(tar: tarfile.TarFile, xml_file_name: str, consignment_reference: str) -> Element:
    xml_file = extract_xml_file(tar, xml_file_name)
    if xml_file:
        contents = xml_file.read()
        try:
            return ET.fromstring(contents)
        except ET.ParseError:
            logger.warning(
                "Invalid XML file for consignment reference: %s. Falling back to parser.log contents.",
                consignment_reference,
            )
    else:
        logger.warning(
            "No XML file found in tarfile. consignment reference: %s. Falling back to parser.log contents.",
            consignment_reference,
        )
    contents = create_parser_log_xml(tar)
    return ET.fromstring(contents)


def extract_source_filename(metadata: DocumentProcessingMetadata, consignment_reference: str) -> str | None:
    try:
        return metadata["parameters"]["TRE"]["payload"]["filename"]
    except KeyError as err:
        raise DocxFilenameNotFoundException(
            f"No source filename was found in metadata. Consignment Ref: {consignment_reference}, metadata: {metadata}",
        ) from err


def modify_filename(original: str, addition: str) -> str:
    "Add an addition after the filename, so TRE-2024-A.tar.gz becomes TRE-2024-A_nodocx.tar.gz"
    path, basename = os.path.split(original)
    # dot will be an empty string if there is no dot in the filename.
    # prefix will be everything upto and not including the first dot.
    prefix, dot, suffix = basename.partition(".")
    new_basename = f"{prefix}{addition}{dot}{suffix}"
    return os.path.join(path, new_basename)

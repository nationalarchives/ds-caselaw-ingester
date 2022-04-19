import os
import json

from typing import Union, Dict, List, Tuple

import boto3
from boto3.session import Session
import urllib3
import tarfile
import xml.etree.ElementTree as ET

from caselawclient.Client import api_client, MarklogicCommunicationError
from botocore.exceptions import NoCredentialsError
from notifications_python_client.notifications import NotificationsAPIClient

import rollbar


rollbar.init(os.getenv('ROLLBAR_TOKEN'), environment=os.getenv('ROLLBAR_ENV'))


class UriNotFoundException(Exception):
    pass


class XmlFileNotFoundException(Exception):
    pass


class DocxNotFoundException(Exception):
    pass


class DocxFilenameNotFoundException(Exception):
    pass


class MaximumRetriesExceededException(Exception):
    pass


def extract_uri(metadata: dict) -> str:
    return metadata["parameters"]["PARSER"]["uri"].replace('https://caselaw.nationalarchives.gov.uk/id/', '')


def extract_docx_filename(metadata: dict) -> str:
    return metadata["parameters"]["TRE"]["payload"]["filename"]


def extract_lambda_versions(versions: List[Dict[str, str]]) -> List[Tuple[str, str]]:
    version_tuples = []
    for d in versions:
        version_tuples += list(d.items())

    return version_tuples


def store_metadata(uri: str, metadata: dict) -> None:
    tdr_metadata = metadata["parameters"]["TDR"]

    # Store source information
    api_client.set_property(uri, name="source-organisation", value=tdr_metadata["Source-Organization"])
    api_client.set_property(uri, name="source-name", value=tdr_metadata["Source-Organization"])
    api_client.set_property(uri, name="source-email", value=tdr_metadata["Contact-Email"])
    # Store TDR data
    api_client.set_property(uri, name="transfer-consignment-reference", value=tdr_metadata["Internal-Sender-Identifier"])
    api_client.set_property(uri, name="transfer-received-at",
                            value=tdr_metadata["Consignment-Completed-Datetime"])


def store_original_document(original_document, uri, s3_client: Session.client):
    filename = f'{uri}/{uri.replace("/", "_")}.docx'

    try:
        s3_client.upload_fileobj(original_document, os.getenv('AWS_BUCKET_NAME'), filename)

        print(f'Upload Successful {filename}')
    except FileNotFoundError:
        print(f'The file {filename} was not found')
    except NoCredentialsError:
        print('Credentials not available')


def send_retry_message(original_message: Dict[str, Union[str, int]], sqs_client: Session.client) -> None:
    number_of_retries = int(original_message["number-of-retries"])
    if number_of_retries <= 3:
        retry_message = {
            "consignment-reference": original_message["consignment-reference"],
            "s3-folder-url": "",
            "consignment-type": original_message["consignment-type"],
            "number-of-retries": number_of_retries + 1
        }
        sqs_client.send_message(
            QueueUrl=os.getenv('SQS_QUEUE_URL'),
            MessageBody=json.dumps(retry_message)
        )
    else:
        raise MaximumRetriesExceededException(f'Maximum number of retries reached for {original_message["consignment-reference"]}')


@rollbar.lambda_function
def handler(event, context):
    decoder = json.decoder.JSONDecoder()
    message = decoder.decode(event['Records'][0]['Sns']['Message'])
    consignment_reference = message["consignment-reference"]

    if os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('AWS_SECRET_KEY') and os.getenv('AWS_ENDPOINT_URL'):
        session = boto3.session.Session(aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                                        aws_secret_access_key=os.getenv('AWS_SECRET_KEY'))
        sqs_client = session.client('sqs', endpoint_url=os.getenv('AWS_ENDPOINT_URL'))
        s3_client = session.client('s3', endpoint_url=os.getenv('AWS_ENDPOINT_URL'))
    else:
        session = boto3.session.Session()
        sqs_client = session.client('sqs')
        s3_client = session.client('s3')
    try:
        # Retrieve tar file from S3
        http = urllib3.PoolManager()
        file = http.request('GET', message["s3-folder-url"])

        # Store it in the /tmp directory
        filename = os.path.join("/tmp", f'{consignment_reference}.tar.gz')
        with open(filename, 'wb') as out:
            out.write(file.data)
            out.close()

        # Extract the judgment XML
        tar = tarfile.open(filename, mode='r')
        te_metadata_file = tar.extractfile(f'{consignment_reference}/TRE-{consignment_reference}-metadata.json')
        metadata = decoder.decode(te_metadata_file.read().decode('utf-8'))

        xml_file_name = metadata["parameters"]["TRE"]["payload"]["xml"]
        xml_file = tar.extractfile(f'{consignment_reference}/{xml_file_name}')

        uri = extract_uri(metadata)

        if not uri:
            raise UriNotFoundException(f'URI not found. Consignment Ref: {consignment_reference}')

        if not xml_file:
            raise XmlFileNotFoundException(f'No XML file was found. Consignment Ref: {consignment_reference}')

        contents = xml_file.read()

        xml = ET.XML(contents)

        try:
            api_client.get_judgment_xml(uri, show_unpublished=True)
            api_client.save_judgment_xml(uri, xml)
            print(f'Updated judgment {uri}')
        except MarklogicCommunicationError:
            api_client.insert_judgment_xml(uri, xml)
            print(f'Inserted judgment {uri}')

        # Store metadata
        store_metadata(uri, metadata)

        docx_filename = extract_docx_filename(metadata)
        if not filename:
            raise DocxFilenameNotFoundException(f'No .docx filename was found in meta. Consignment Ref: {consignment_reference}')

        original_document = tar.extractfile(f'{consignment_reference}/{docx_filename}')
        if original_document:
            store_original_document(original_document, uri, s3_client)
        else:
            raise DocxNotFoundException(f'No .docx file was found. Consignment Ref: {consignment_reference}, expected file: {docx_filename}')

    except BaseException:
        # Send retry message to sqs
        send_retry_message(message, sqs_client)
        # Raise error up to ensure it's logged
        raise

    return message

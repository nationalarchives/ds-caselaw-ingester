import os
import json

from typing import Union, Dict, List, Tuple

import boto3
from boto3.session import Session
import urllib3
import tarfile
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from caselawclient.Client import api_client, MarklogicCommunicationError, MarklogicResourceNotFoundError
from botocore.exceptions import NoCredentialsError
from notifications_python_client.notifications import NotificationsAPIClient

import rollbar


rollbar.init(os.getenv('ROLLBAR_TOKEN'), environment=os.getenv('ROLLBAR_ENV'))


class XmlFileNotFoundException(Exception):
    pass


class FileNotFoundException(Exception):
    pass


class DocxFilenameNotFoundException(Exception):
    pass


class MaximumRetriesExceededException(Exception):
    pass


def extract_uri(metadata: dict, consignment_reference: str) -> str:
    uri = metadata["parameters"]["PARSER"].get("uri", "").replace('https://caselaw.nationalarchives.gov.uk/id/', '')

    if not uri:
        uri = f'failures/{consignment_reference}'

    return uri


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
    api_client.set_property(uri, name="source-name", value=tdr_metadata["Contact-Name"])
    api_client.set_property(uri, name="source-email", value=tdr_metadata["Contact-Email"])
    # Store TDR data
    api_client.set_property(uri, name="transfer-consignment-reference", value=tdr_metadata["Internal-Sender-Identifier"])
    api_client.set_property(uri, name="transfer-received-at",
                            value=tdr_metadata["Consignment-Completed-Datetime"])


def store_file(file, folder, filename, s3_client: Session.client):
    pathname = f'{folder}/{filename}'
    try:
        s3_client.upload_fileobj(file, os.getenv('AWS_BUCKET_NAME'), pathname)
        print(f'Upload Successful {pathname}')
    except FileNotFoundError:
        print(f'The file {pathname} was not found')
    except NoCredentialsError:
        print('Credentials not available')

def send_new_judgment_notification(uri: str, metadata: dict):
    tdr_metadata = metadata["parameters"]["TDR"]
    notifications_client = NotificationsAPIClient(os.getenv('NOTIFY_API_KEY'))
    response = notifications_client.send_email_notification(
        email_address=os.getenv('NOTIFY_EDITORIAL_ADDRESS'),
        template_id=os.getenv('NOTIFY_NEW_JUDGMENT_TEMPLATE_ID'),
        personalisation={
            'url': f'{os.getenv("EDITORIAL_UI_BASE_URL")}detail?judgment_uri={uri}',
            'consignment': tdr_metadata["Internal-Sender-Identifier"],
            'submitter': f'{tdr_metadata["Contact-Name"]}, {tdr_metadata["Source-Organization"]} <{tdr_metadata["Contact-Email"]}>',
            'submitted_at': tdr_metadata["Consignment-Completed-Datetime"]
        }
    )
    print(f'Sent notification to {os.getenv("NOTIFY_EDITORIAL_ADDRESS")} (Message ID: {response["id"]})')

def send_updated_judgment_notification(uri: str, metadata: dict):
    tdr_metadata = metadata["parameters"]["TDR"]
    notifications_client = NotificationsAPIClient(os.getenv('NOTIFY_API_KEY'))
    response = notifications_client.send_email_notification(
        email_address=os.getenv('NOTIFY_EDITORIAL_ADDRESS'),
        template_id=os.getenv('NOTIFY_UPDATED_JUDGMENT_TEMPLATE_ID'),
        personalisation={
            'url': f'{os.getenv("EDITORIAL_UI_BASE_URL")}detail?judgment_uri={uri}',
            'consignment': tdr_metadata["Internal-Sender-Identifier"],
            'submitter': f'{tdr_metadata["Contact-Name"]}, {tdr_metadata["Source-Organization"]} <{tdr_metadata["Contact-Email"]}>',
            'submitted_at': tdr_metadata["Consignment-Completed-Datetime"]
        }
    )
    print(f'Sent notification to {os.getenv("NOTIFY_EDITORIAL_ADDRESS")} (Message ID: {response["id"]})')

def copy_file(tarfile, input_filename, output_filename, uri, s3_client: Session.client):
    file = tarfile.extractfile(input_filename)
    if file:
        store_file(file, uri, output_filename, s3_client)
    else:
        raise FileNotFoundException(f'File was not found: {input_filename}')

def send_retry_message(original_message: Dict[str, Union[str, int]], sqs_client: Session.client) -> None:
    retry_number = int(original_message["number-of-retries"]) + 1
    if retry_number <= int(os.getenv("MAX_RETRIES", "5")):
        retry_message = {
            "consignment-reference": original_message["consignment-reference"],
            "s3-folder-url": "",
            "consignment-type": original_message["consignment-type"],
            "number-of-retries": retry_number
        }
        sqs_client.send_message(
            QueueUrl=os.getenv('SQS_QUEUE_URL'),
            MessageBody=json.dumps(retry_message)
        )
    else:
        raise MaximumRetriesExceededException(f'Maximum number of retries reached for {original_message["consignment-reference"]}')


def create_error_xml_contents(tar, consignment_reference: str):
    parser_log = tar.extractfile(f'{consignment_reference}/parser.log')
    parser_log_contents = escape(parser_log.read().decode('utf-8'))
    return f'<error>{parser_log_contents}</error>'


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
        try:
            xml_file = tar.extractfile(f'{consignment_reference}/{xml_file_name}')
        except KeyError:
            xml_file = None

        uri = extract_uri(metadata, consignment_reference)

        if xml_file:
            contents = xml_file.read()
        elif 'failures' in uri:
            contents = create_error_xml_contents(tar, consignment_reference)
        else:
            raise XmlFileNotFoundException(f'No XML file was found. Consignment Ref: {consignment_reference}')

        ET.register_namespace("", "http://docs.oasis-open.org/legaldocml/ns/akn/3.0")
        ET.register_namespace("uk", "https://caselaw.nationalarchives.gov.uk/akn")
        xml = ET.XML(contents)

        try:
            api_client.get_judgment_xml(uri, show_unpublished=True)
            api_client.save_judgment_xml(uri, xml)
            # Notify editors that a document has been updated
            send_updated_judgment_notification(uri, metadata)
            print(f'Updated judgment {uri}')
        except MarklogicResourceNotFoundError:
            api_client.insert_judgment_xml(uri, xml)
            # Notify editors that a new document is ready
            send_new_judgment_notification(uri, metadata)
            print(f'Inserted judgment {uri}')

        # Store metadata
        store_metadata(uri, metadata)

        # Store docx and rename
        docx_filename = extract_docx_filename(metadata)
        if not filename:
            raise DocxFilenameNotFoundException(f'No .docx filename was found in meta. Consignment Ref: {consignment_reference}')
        copy_file(tar, f'{consignment_reference}/{docx_filename}', f'{uri.replace("/", "_")}.docx', uri, s3_client)

        # Store parser log
        copy_file(tar, f'{consignment_reference}/parser.log', 'parser.log', uri, s3_client)

        # Store images
        for image_filename in metadata["parameters"]["TRE"]["payload"]["images"]:
            copy_file(tar, f'{consignment_reference}/{image_filename}', image_filename, uri, s3_client)

        # Copy original tarfile
        store_file(open(filename, mode='rb'), uri, os.path.basename(filename), s3_client)

    except (urllib3.exceptions.ProtocolError, tarfile.ReadError):
        # Send retry message to sqs
        send_retry_message(message, sqs_client)
        # Raise error up to ensure it's logged
        raise
    except BaseException:
        raise

    return message

import os
import json
import datetime

from typing import Union, Dict, List, Tuple

import boto3
from boto3.session import Session
from requests_toolbelt.multipart.decoder import MultipartDecoder
import urllib3
import tarfile
import xml.etree.ElementTree as ET

from caselawclient.Client import api_client, MarklogicCommunicationError
from botocore.exceptions import NoCredentialsError

COURT_TO_URI = {
    "UKSC": "uksc",
    "UKPC": "ukpc",
    "EWCA ": "ewca",
    "EWHC": "ewhc",
    "EWCOP": "ewcop",
    "EWFC": "ewfc",
    "EWCA-Civil": "ewca/civ",
    "EWCA-Criminal": "ewca/crim",
    "EWHC-QBD": "ewhc/qb",
    "EWHC-Chancery": "ewhc/ch",
    "EWHC-Family": "ewhc/fam",
    "EWHC-QBD-General": "ewhc/qb",
    "EWHC-QBD-Admin": "ewhc/qb",
    "EWHC-QBD-Plannig": "ewhc/qb",
    "EWHC-QBD-BusinessAndProperty": "ewhc/qb",
    "EWHC-QBD-Commercial": "ewhc/qb"
}


def extract_uri(contents: str) -> str:
    decoder = json.decoder.JSONDecoder()
    metadata = decoder.decode(contents)
    return metadata["uri"].replace('https://caselaw.nationalarchives.gov.uk/id/', '')


def extract_lambda_versions(versions: List[Dict[str, str]]) -> List[Tuple[str, str]]:
    version_tuples = []
    for d in versions:
        version_tuples += list(d.items())

    return version_tuples


def store_metadata(uri: str, metadata: Dict[str, Union[str, dict, List[dict]]]) -> None:
    api_client.set_property(uri, name="tre-version", value=metadata["int-tre-version"])
    api_client.set_property(uri, name="text-parser-version", value=metadata["text-parser-version"])

    for key, version in extract_lambda_versions(metadata["lambda-functions-version"]):
        api_client.set_property(uri, name=f'lambda-{key}', value=version)

    api_client.set_property(uri, name="source-organisation", value=metadata["bagit-info"]["Source-Organization"])
    api_client.set_property(uri, name="contact-name", value=metadata["bagit-info"]["Contact-Name"])
    api_client.set_property(uri, name="consignment-reference",
                            value=metadata["bagit-info"]["Internal-Sender-Identifier"])
    api_client.set_property(uri, name="publish-datetime",
                            value=metadata["bagit-info"]["Consignment-Completed-Datetime"])
    api_client.set_property(uri, name="contact-email", value=metadata["bagit-info"]["Contact-Email"])


def store_original_document(original_document, uri, session: Session):
    s3 = session.client('s3', endpoint_url=os.getenv('AWS_ENDPOINT_URL'))
    filename = f'{uri}.docx'

    try:
        s3.upload_fileobj(original_document, os.getenv('AWS_BUCKET_NAME'), filename)

        print(f'Upload Successful {filename}')
    except FileNotFoundError:
        print(f'The file {filename} was not found')
    except NoCredentialsError:
        print('Credentials not available')


def send_retry_message(original_message: Dict[str, Union[str, int]], session: Session) -> None:
    sqs = session.client('sqs', endpoint_url=os.getenv('AWS_ENDPOINT_URL'))
    retry_message = {
        "consignment-reference": original_message["consignment-reference"],
        "s3-folder-url": "",
        "consignment-type": original_message["consignment-type"],
        "number-of-retries": int(original_message["number-of-retries"]) + 1
    }
    sqs.send_message(
        QueueUrl=os.getenv('SQS_QUEUE_URL'),
        MessageBody=json.dumps(retry_message)
    )


def handler(event, context):
    decoder = json.decoder.JSONDecoder()
    message = decoder.decode(event['Records'][0]['Sns']['Message'])
    consignment_reference = message["consignment-reference"]

    session = boto3.session.Session(aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                                    aws_secret_access_key=os.getenv('AWS_SECRET_KEY'))
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
        xml_file = tar.extractfile(f'{consignment_reference}/{consignment_reference}.xml')

        te_meta = tar.extractfile(f'{consignment_reference}/te-meta.json')
        uri = extract_uri(te_meta.read().decode('utf-8'))

        te_metadata_file = tar.extractfile(f'{consignment_reference}/te-metadata.json')
        metadata = decoder.decode(te_metadata_file.read().decode('utf-8'))

        if xml_file and uri:
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

            original_document = tar.extractfile(f'{consignment_reference}/{consignment_reference}.docx')
            if original_document:
                store_original_document(original_document, uri, session)

        elif xml_file and not uri:
            # There is no URI set, so we must assign an ordinal ID and create a new URI
            date = datetime.datetime.strptime(
                metadata["bagit-info"]["Consignment-Completed-Datetime"],
                "%Y-%m-%dT%H:%M:%SZ"
            ).strftime("%Y-%m-%d")

            response = api_client.advanced_search(date_from=date, date_to=date, show_unpublished=True)
            results = MultipartDecoder.from_response(response).parts[0].text

            xml = ET.fromstring(results)
            ns = {
                "search": "http://marklogic.com/appservices/search",
                "akn": "http://docs.oasis-open.org/legaldocml/ns/akn/3.0",
                "uk": "https://caselaw.nationalarchives.gov.uk/akn",
            }
            total = int(xml.find(".//search:response/@total", namespaces=ns).text)
            court = xml.find(".//akn:proprietary/uk:court", namespaces=ns).text

            court_uri = COURT_TO_URI[court]
            # Get all documents published on the same day
            ordinal_id = total + 1
            # Create a new URI for the document in the format:
            # <court>/<?subdivision>/<year>/<date>/num/ordinal_id


    except BaseException:
        # Send retry message to sqs
        send_retry_message(message, session)
        # Raise error up to ensure it's logged
        raise

    return message

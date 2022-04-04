import os
import json
from typing import Union, Dict, List, Tuple

import urllib3
import tarfile
import xml.etree.ElementTree as ET

from caselawclient.Client import api_client, MarklogicCommunicationError


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
    api_client.set_property(uri, name="consignment-reference", value=metadata["bagit-info"]["Internal-Sender-Identifier"])
    api_client.set_property(uri, name="publish-datetime",
                            value=metadata["bagit-info"]["Consignment-Completed-Datetime"])
    api_client.set_property(uri, name="contact-email", value=metadata["bagit-info"]["Contact-Email"])


def handler(event, context):
    decoder = json.decoder.JSONDecoder()
    message = decoder.decode(event['Records'][0]['Sns']['Message'])
    consignment_reference = message["consignment-reference"]

    # Retrieve tar file from S3
    http = urllib3.PoolManager()
    file = http.request('GET', message["s3-folder-url"])

    # Store it in the /tmp directory
    filename = os.path.join("/tmp", f'{consignment_reference}.tar.gz')
    with open(filename, 'wb') as out:
        out.write(file.data)

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

    return message

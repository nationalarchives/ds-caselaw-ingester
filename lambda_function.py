import os
import json
import urllib3
import tarfile


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

    if xml_file:
        print(xml_file.read())

    return message

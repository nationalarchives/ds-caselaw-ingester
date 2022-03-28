import os
import json
import urllib3

def handler(event, context):
    decoder = json.decoder.JSONDecoder()
    message = decoder.decode(event['Records'][0]['Sns']['Message'])
    print("Consignment reference:", message["consignment-reference"])
    http = urllib3.PoolManager()
    metadata_file = http.request('GET', message["s3-folder-url"])
    metadata = decoder.decode(metadata_file.data.decode('utf-8'))
    print(metadata["bagit-info"]["Internal-Sender-Identifier"])
    return message

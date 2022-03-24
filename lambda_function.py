import json


def handler(event, context):
    decoder = json.decoder.JSONDecoder()
    message = decoder.decode(event['Records'][0]['Sns']['Message'])
    print("Consignment reference:", message["consignment-reference"])
    return message

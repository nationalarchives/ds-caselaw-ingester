import json

v2_message_raw = """
    {
        "properties": {
            "messageType":
                "uk.gov.nationalarchives.tre.messages.judgmentpackage.available.JudgmentPackageAvailable",
            "timestamp": "2023-05-15T09:14:53.791409Z",
            "function": "staging-tre-judgment-packer-lambda",
            "producer": "TRE",
            "executionId": "cc46e39f-76ef-43c9-a6d7-c6b064c3556a",
            "parentExecutionId": "d26458ae-19a7-4159-8381-805075163198"
        },
        "parameters": {
            "status": "JUDGMENT_PARSE_NO_ERRORS",
            "reference": "TDR-2022-DNWR",
            "originator": "TDR",
            "bundleFileURI": "http://172.17.0.2:4566/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
            "metadataFilePath": "/metadata.json",
            "metadataFileType": "Json"
        }
    }
    """

s3_message = {
    "Records": [
        {
            "eventSource": "aws:s3",
            "s3": {
                "bucket": {
                    "name": "staging-tre-court-document-pack-out",
                },
                "object": {
                    "key": "QX/e31b117f-ff09-49b6-a697-7952c7a67384/BULK-0.tar.gz",
                },
            },
        },
    ],
}
v2_message = json.loads(v2_message_raw)
s3_message_raw = json.dumps(s3_message)

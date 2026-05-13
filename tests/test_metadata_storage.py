from unittest.mock import MagicMock, call

import rollbar

from src.ds_caselaw_ingester import ingester

rollbar.init(access_token=None, enabled=False)


class TestMetadataStorage:
    def test_perform_ingest_calls_tdr_metadata_storage_when_tdr_present(self):
        ingest = MagicMock()
        ingest.metadata = {
            "parameters": {
                "TDR": {"test-property": "123"},
            },
        }
        ingester.perform_ingest(ingest)
        ingest.store_tdr_metadata.assert_called_with({"test-property": "123"})

    def test_perform_ingest_calls_tdr_metadata_storage_when_tdr_not_present(self):
        ingest = MagicMock()
        ingest.metadata = {
            "parameters": {},
        }
        ingester.perform_ingest(ingest)
        ingest.store_tdr_metadata.assert_not_called()

    def test_store_tdr_metadata_values(self, v2_ingest):
        v2_ingest.uri = "uri"
        v2_ingest.api_client.set_property = MagicMock()

        v2_ingest.store_tdr_metadata(
            {
                "Source-Organization": "Ministry of Justice",
                "Contact-Name": "Tom King",
                "Internal-Sender-Identifier": "TDR-2021-CF6L",
                "Consignment-Completed-Datetime": "2021-12-16T14:54:06Z",
                "Contact-Email": "someone@example.com",
                "Judgment-Neutral-Citation": "[2019] UKSC 1701",
            },
        )

        v2_ingest.api_client.set_property.assert_has_calls(
            [
                call("uri", name="source-organisation", value="Ministry of Justice"),
                call("uri", name="source-name", value="Tom King"),
                call("uri", name="source-email", value="someone@example.com"),
                call("uri", name="transfer-consignment-reference", value="TDR-2021-CF6L"),
                call("uri", name="transfer-received-at", value="2021-12-16T14:54:06Z"),
            ],
        )

    def test_perform_ingest_calls_parser_metadata_storage_when_tdr_present(self):
        ingest = MagicMock()
        ingest.metadata = {
            "parameters": {
                "PARSER": {"test-property": "123"},
            },
        }
        ingester.perform_ingest(ingest)
        ingest.store_parser_metadata.assert_called_with({"test-property": "123"})

    def test_perform_ingest_calls_parser_metadata_storage_when_tdr_not_present(self):
        ingest = MagicMock()
        ingest.metadata = {
            "parameters": {},
        }
        ingester.perform_ingest(ingest)
        ingest.store_parser_metadata.assert_not_called()

    def test_store_parser_metadata_values(self, v2_ingest):
        v2_ingest.uri = "uri"
        v2_ingest.api_client.set_property = MagicMock()

        v2_ingest.store_parser_metadata({"parser_run_id": "607e7ef1-3b5e-431b-b115-bb1811767f5c"})

        v2_ingest.api_client.set_property.assert_has_calls(
            [
                call("uri", name="parser-run-id", value="607e7ef1-3b5e-431b-b115-bb1811767f5c"),
            ],
        )

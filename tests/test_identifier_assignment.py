from unittest.mock import MagicMock

from caselawclient.factories import JudgmentFactory, PressSummaryFactory
from caselawclient.models.identifiers.neutral_citation import NeutralCitationNumber
from caselawclient.models.identifiers.press_summary_ncn import PressSummaryRelatedNCNIdentifier

from ds_caselaw_ingester import ingester


class TestDocumentIdentifiers:
    """Check that given a document of a given type we assign the correct document-specific identifier types."""

    def test_select_type_press_summary(self):
        ingest = MagicMock()
        ingest.uri = "jam/1/ps/1"

        doc = PressSummaryFactory.build()
        doc.identifiers = MagicMock()
        doc.save_identifiers = MagicMock()
        doc.neutral_citation = "[2013] UKSC 1"
        ingest.api_client.get_document_by_uri.return_value = doc

        ingester.Ingest.set_document_identifiers(ingest)
        assert type(doc.identifiers.add.call_args_list[0].args[0]) is PressSummaryRelatedNCNIdentifier
        doc.save_identifiers.assert_called()

    def test_select_type_judgment(self):
        ingest = MagicMock()
        ingest.uri = "jam/1"

        doc = JudgmentFactory.build()
        doc.identifiers = MagicMock()
        doc.save_identifiers = MagicMock()
        doc.neutral_citation = "[2013] UKSC 1"
        ingest.api_client.get_document_by_uri.return_value = doc

        ingester.Ingest.set_document_identifiers(ingest)
        assert type(doc.identifiers.add.call_args_list[0].args[0]) is NeutralCitationNumber
        doc.save_identifiers.assert_called()

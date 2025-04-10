from unittest.mock import MagicMock

from caselawclient.factories import JudgmentFactory, PressSummaryFactory
from caselawclient.models.identifiers.neutral_citation import NeutralCitationNumber
from caselawclient.models.identifiers.press_summary_ncn import PressSummaryRelatedNCNIdentifier
from caselawclient.models.judgments import Judgment
from caselawclient.models.parser_logs import ParserLog
from caselawclient.models.press_summaries import PressSummary
from pytest import raises

from src.ds_caselaw_ingester import ingester
from src.ds_caselaw_ingester.exceptions import DocumentXMLNotYetInDatabase


class TestDocumentIdentifiers:
    """Check that given a document with known properties we assign (or not) the right identifiers."""

    def test_assign_identifiers_raises_exception_if_no_document(self):
        ingest = MagicMock()
        ingest.ingested_document_type = PressSummary
        ingest.uri = "d-9999"

        ingest.document = None

        with raises(DocumentXMLNotYetInDatabase):
            ingester.Ingest.set_document_identifiers(ingest)

    def test_document_without_ncn_does_not_assign_identifiers(self):
        ingest = MagicMock()
        ingest.ingested_document_type = PressSummary
        ingest.uri = "d-1000"

        doc = PressSummaryFactory.build()

        doc.neutral_citation = None

        doc.identifiers = MagicMock()
        doc.save_identifiers = MagicMock()

        ingest.document = doc

        ingester.Ingest.set_document_identifiers(ingest)

        doc.identifiers.add.assert_not_called()

        doc.save_identifiers.assert_not_called()

    def test_press_summary_assigns_correct_identifiers(self):
        ingest = MagicMock()
        ingest.ingested_document_type = PressSummary
        ingest.uri = "d-1001"

        doc = PressSummaryFactory.build()
        doc.identifiers = MagicMock()
        doc.save_identifiers = MagicMock()
        doc.neutral_citation = "[2013] UKSC 1"

        ingest.document = doc

        ingester.Ingest.set_document_identifiers(ingest)

        new_identifier = doc.identifiers.add.call_args_list[0].args[0]
        assert type(new_identifier) is PressSummaryRelatedNCNIdentifier
        assert new_identifier.value == "[2013] UKSC 1"

        doc.save_identifiers.assert_called()

    def test_judgment_assigns_correct_identifiers(self):
        ingest = MagicMock()
        ingest.ingested_document_type = Judgment
        ingest.uri = "d-1002"

        doc = JudgmentFactory.build()
        doc.identifiers = MagicMock()
        doc.save_identifiers = MagicMock()
        doc.neutral_citation = "[2013] UKSC 1"

        ingest.document = doc

        ingester.Ingest.set_document_identifiers(ingest)

        new_identifier = doc.identifiers.add.call_args_list[0].args[0]
        assert type(new_identifier) is NeutralCitationNumber
        assert new_identifier.value == "[2013] UKSC 1"

        doc.save_identifiers.assert_called()

    def test_parser_log_assigns_correct_identifiers(self):
        """Verify parser error documents do not get identifiers"""
        ingest = MagicMock()
        ingest.ingested_document_type = ParserLog
        ingest.uri = "d-1003"

        doc = JudgmentFactory.build()
        doc.identifiers = MagicMock()
        doc.save_identifiers = MagicMock()
        doc.neutral_citation = None

        ingest.document = doc

        ingester.Ingest.set_document_identifiers(ingest)

        doc.identifiers.add.assert_not_called()

        doc.save_identifiers.assert_not_called()

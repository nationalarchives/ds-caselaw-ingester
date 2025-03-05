from caselawclient.models.judgments import Judgment
from caselawclient.models.press_summaries import PressSummary
from pytest import raises

from ds_caselaw_ingester.exceptions import CannotDetermineDocumentType
from ds_caselaw_ingester.ingester import parse_xml


class TestIngestProperties:
    def test_ingested_document_type_judgment(self, v2_ingest):
        """Check that documents with a root tag of `<judgment>` are detected as `Judgment`s."""
        v2_ingest.xml = parse_xml(b"<judgment />")
        assert v2_ingest.ingested_document_type == Judgment

    def test_ingested_document_type_press_summary(self, v2_ingest):
        """ "Check that documents with a root tag of `<doc name="pressSummary">` are detected as `PressSummary`s."""
        v2_ingest.xml = parse_xml(b'<doc name="pressSummary" />')
        assert v2_ingest.ingested_document_type == PressSummary

    def test_ingested_document_type_doc_without_press_summary_name(self, v2_ingest):
        """ "Check that documents with a root tag of `<doc>` but no `name="pressSummary" raise an exception."""
        v2_ingest.xml = parse_xml(b"<doc />")
        with raises(CannotDetermineDocumentType):
            assert v2_ingest.ingested_document_type

    def test_ingested_document_type_unknown(self, v2_ingest):
        """Check that in the absence of typing information an exception is raised."""
        with raises(CannotDetermineDocumentType):
            assert v2_ingest.ingested_document_type

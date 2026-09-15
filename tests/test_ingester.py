from unittest.mock import ANY, MagicMock, patch

import lxml.etree as ET
import pytest
from caselawclient.Client import (
    MarklogicCommunicationError,
)
from caselawclient.models.documents.exceptions import CannotPublishUnpublishableDocument
from caselawclient.models.documents.versions import VersionType
from caselawclient.models.judgments import Judgment
from caselawclient.models.parser_logs import ParserLog
from caselawclient.models.press_summaries import PressSummary

from src.ds_caselaw_ingester import ingester
from src.ds_caselaw_ingester.exceptions import DocumentInsertionError, IngestionError


class TestPerformIngest:
    def test_perform_ingest_raises_reportable_error_if_unpublishable(self):
        """If the document is not publishable, make sure an IngestionError is raised."""
        ingest = MagicMock()
        ingest.will_publish.return_value = True
        ingest.document.publish.side_effect = CannotPublishUnpublishableDocument("Publishing failed")
        with pytest.raises(IngestionError, match="^Publishing failed$"):
            ingester.perform_ingest(ingest)


class TestSaveDocumentToMarklogic:
    def test_save_document_to_marklogic_update_path(self, v2_ingest):
        document = MagicMock()
        v2_ingest.exists_in_database = True
        v2_ingest.api_client.get_document_by_uri = MagicMock(return_value=document)

        result = v2_ingest.save_document_to_marklogic()

        assert result is document
        document.save.assert_called_once_with(
            message="Updated document submitted by TDR user",
            version_type=VersionType.SUBMISSION,
            automated=False,
            payload=ANY,
        )

    def test_save_document_to_marklogic_update_path_no_tdr(self, v2_ingest):
        document = MagicMock()
        v2_ingest.exists_in_database = True
        v2_ingest.metadata = {"parameters": {}}
        v2_ingest.api_client.get_document_by_uri = MagicMock(return_value=document)

        v2_ingest.save_document_to_marklogic()

        document.save.assert_called_once_with(
            message="Updated document uploaded by Find Case Law",
            version_type=VersionType.SUBMISSION,
            automated=False,
            payload=ANY,
        )

    @patch("src.ds_caselaw_ingester.ingester.document_from_xml")
    def test_save_document_to_marklogic_insert_judgment(self, document_from_xml, v2_ingest):
        xml = ET.XML(
            "<akomaNtoso xmlns='http://docs.oasis-open.org/legaldocml/ns/akn/3.0'><judgment><xml>Here's some xml</xml></judgment></akomaNtoso>",
        )
        document = MagicMock(spec=Judgment)
        document_from_xml.return_value = document
        v2_ingest.exists_in_database = False
        v2_ingest.uri = "a/fake/uri"
        v2_ingest.xml = xml

        v2_ingest.save_document_to_marklogic()

        document_from_xml.assert_called_once()
        document.save.assert_called_once_with(
            message="New document submitted by TDR user",
            version_type=VersionType.SUBMISSION,
            automated=False,
            payload=ANY,
        )

    @patch("src.ds_caselaw_ingester.ingester.document_from_xml")
    def test_save_document_to_marklogic_insert_press_summary(self, document_from_xml, v2_ingest):
        xml = ET.XML(
            "<akomaNtoso xmlns='http://docs.oasis-open.org/legaldocml/ns/akn/3.0'><doc name='pressSummary'><xml>Here's some xml</xml></doc></akomaNtoso>",
        )
        document = MagicMock(spec=PressSummary)
        document_from_xml.return_value = document
        v2_ingest.exists_in_database = False
        v2_ingest.uri = "a/fake/uri"
        v2_ingest.xml = xml

        v2_ingest.save_document_to_marklogic()

        document_from_xml.assert_called_once()
        document.save.assert_called_once()

    @patch("src.ds_caselaw_ingester.ingester.document_from_xml")
    def test_save_document_to_marklogic_insert_parser_log(self, document_from_xml, v2_ingest):
        xml = ET.XML("<error/>")
        document = MagicMock(spec=ParserLog)
        document_from_xml.return_value = document
        v2_ingest.exists_in_database = False
        v2_ingest.uri = "a/fake/uri"
        v2_ingest.xml = xml

        v2_ingest.save_document_to_marklogic()

        document_from_xml.assert_called_once()
        document.save.assert_called_once()

    @patch("src.ds_caselaw_ingester.ingester.document_from_xml")
    def test_save_document_to_marklogic_insert_failure(self, document_from_xml, v2_ingest):
        document = MagicMock()
        document.save.side_effect = MarklogicCommunicationError("error")
        document_from_xml.return_value = document
        v2_ingest.exists_in_database = False

        with pytest.raises(MarklogicCommunicationError):
            v2_ingest.save_document_to_marklogic()

    def test_insert_or_update_xml_raises_error_with_uri_and_consignment_when_existing_disallowed(self, v2_ingest):
        v2_ingest.exists_in_database = True
        v2_ingest.uri = "ewca/civ/2026/42"
        v2_ingest.consignment_reference = "TDR-2026-ABCD"
        v2_ingest.metadata = {
            "parameters": {
                "INGESTER_OPTIONS": {
                    "error_on_existing_document": True,
                },
            },
        }

        with pytest.raises(DocumentInsertionError) as err:
            v2_ingest.insert_or_update_xml()

        assert (
            str(err.value)
            == "A match for this document already exists in the database at ewca/civ/2026/42. Consignment Ref: TDR-2026-ABCD"
        )

    def test_insert_or_update_xml_updates_existing_when_existing_allowed(self, v2_ingest):
        v2_ingest.exists_in_database = True
        v2_ingest.metadata = {
            "parameters": {
                "INGESTER_OPTIONS": {
                    "error_on_existing_document": False,
                },
            },
        }
        document = MagicMock()
        v2_ingest.save_document_to_marklogic = MagicMock(return_value=document)

        v2_ingest.insert_or_update_xml()

        v2_ingest.save_document_to_marklogic.assert_called_once()
        assert v2_ingest.document is document

    def test_insert_or_update_xml_wraps_save_failures(self, v2_ingest):
        v2_ingest.exists_in_database = False
        v2_ingest.uri = "ewca/civ/2026/42"
        v2_ingest.consignment_reference = "TDR-2026-ABCD"
        v2_ingest.save_document_to_marklogic = MagicMock(side_effect=RuntimeError("boom"))

        with pytest.raises(DocumentInsertionError) as err:
            v2_ingest.insert_or_update_xml()

        assert str(err.value) == "Inserting judgment ewca/civ/2026/42 failed. Consignment Ref: TDR-2026-ABCD"

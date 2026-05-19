from unittest.mock import ANY, MagicMock

import lxml.etree as ET
import pytest
from caselawclient.Client import (
    MarklogicCommunicationError,
)
from caselawclient.models.documents.exceptions import CannotPublishUnpublishableDocument
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


class TestInsertUpdateOperations:
    def test_update_document_xml_success(self, v2_ingest):
        v2_ingest.api_client.get_judgment_xml = MagicMock(return_value=True)
        v2_ingest.api_client.update_document_xml = MagicMock(return_value=True)
        v2_ingest.update_document_xml()

    def test_update_document_xml_success_no_tdr(self, v2_ingest):
        v2_ingest.api_client.get_judgment_xml = MagicMock(return_value=True)
        v2_ingest.api_client.update_document_xml = MagicMock(return_value=True)
        v2_ingest.metadata = {"parameters": {}}
        v2_ingest.update_document_xml()

    def test_insert_document_xml_success_judgment(self, v2_ingest):
        xml = ET.XML(
            "<akomaNtoso xmlns='http://docs.oasis-open.org/legaldocml/ns/akn/3.0'><judgment><xml>Here's some xml</xml></judgment></akomaNtoso>",
        )
        v2_ingest.api_client.insert_document_xml = MagicMock(return_value=True)
        v2_ingest.uri = "a/fake/uri"
        v2_ingest.xml = xml
        v2_ingest.insert_document_xml()
        v2_ingest.api_client.insert_document_xml.assert_called_once_with(
            document_uri=v2_ingest.uri,
            document_xml=xml,
            annotation=ANY,
            document_type=Judgment,
        )

    def test_insert_document_xml_success_press_summary(self, v2_ingest):
        xml = ET.XML(
            "<akomaNtoso xmlns='http://docs.oasis-open.org/legaldocml/ns/akn/3.0'><doc name='pressSummary'><xml>Here's some xml</xml></doc></akomaNtoso>",
        )
        v2_ingest.api_client.insert_document_xml = MagicMock(return_value=True)
        v2_ingest.uri = "a/fake/uri"
        v2_ingest.xml = xml
        v2_ingest.insert_document_xml()
        v2_ingest.api_client.insert_document_xml.assert_called_once_with(
            document_uri=v2_ingest.uri,
            document_xml=xml,
            annotation=ANY,
            document_type=PressSummary,
        )

    def test_insert_document_xml_parser_error(self, v2_ingest):
        """Parser errors are successfully imported with document type Error"""
        xml = ET.XML(
            "<error/>",
        )
        v2_ingest.api_client.insert_document_xml = MagicMock(return_value=True)
        v2_ingest.uri = "a/fake/uri"
        v2_ingest.xml = xml
        v2_ingest.insert_document_xml()
        v2_ingest.api_client.insert_document_xml.assert_called_once_with(
            document_uri=v2_ingest.uri,
            document_xml=xml,
            annotation=ANY,
            document_type=ParserLog,
        )

    def test_insert_document_xml_failure(self, v2_ingest):
        v2_ingest.api_client.insert_document_xml = MagicMock(side_effect=MarklogicCommunicationError("error"))
        with pytest.raises(MarklogicCommunicationError):
            v2_ingest.insert_document_xml()

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
            == "Document already exists in the database at ewca/civ/2026/42. Consignment Ref: TDR-2026-ABCD"
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
        v2_ingest.update_document_xml = MagicMock()
        v2_ingest.api_client.get_document_by_uri = MagicMock(return_value=MagicMock())

        v2_ingest.insert_or_update_xml()

        v2_ingest.update_document_xml.assert_called_once()

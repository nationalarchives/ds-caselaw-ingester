from unittest.mock import MagicMock

import pytest
from caselawclient.models.documents.exceptions import CannotPublishUnpublishableDocument

from src.ds_caselaw_ingester import ingester
from src.ds_caselaw_ingester.exceptions import IngestionError


class TestPerformIngest:
    def test_perform_ingest_raises_reportable_error_if_unpublishable(self):
        """If the document is not publishable, make sure an IngestionError is raised."""
        ingest = MagicMock()
        ingest.will_publish.return_value = True
        ingest.document.publish.side_effect = CannotPublishUnpublishableDocument("Publishing failed")
        with pytest.raises(IngestionError, match="^Publishing failed$"):
            ingester.perform_ingest(ingest)

import os
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
import rollbar
from notifications_python_client.notifications import NotificationsAPIClient

from .helpers import (
    assert_log_has_message_starting,
)

rollbar.init(access_token=None, enabled=False)

NULL_UPDATE_METADATA = '{\n  "Judgment-Update": null,\n  "Judgment-Update-Type": null,\n  "Judgment-Update-Details": null,\n  "Judgment-Neutral-Citation": null,\n  "Judgment-No-Neutral-Citation": null,\n  "Judgment-Reference": null\n}'


class TestNotifications:
    @patch.dict(
        os.environ,
        {
            "NOTIFY_API_KEY": "ingester-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "EDITORIAL_UI_BASE_URL": "http://editor.url/",
            "NOTIFY_EDITORIAL_ADDRESS": "test@notifications.service.gov.uk",
            "NOTIFY_NEW_JUDGMENT_TEMPLATE_ID": "template-id",
            "ROLLBAR_ENV": "prod",
        },
        clear=True,
    )
    def test_send_new_judgment_notification(self, v2_ingest, caplog: pytest.LogCaptureFixture):
        v2_ingest.uri = "d-4444"
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=d-4444",
            "consignment": "TDR-2021-CF6L",
            "submitter": "Tom King, Ministry of Justice <someone@example.com>",
            "submitted_at": "2021-12-16T14:54:06Z",
            "doctype": "judgment",
            "update_metadata": NULL_UPDATE_METADATA,
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_new_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )

        assert_log_has_message_starting(caplog, "Sent new notification to test@notifications.service.gov.uk")

    @patch.dict(
        os.environ,
        {
            "NOTIFY_API_KEY": "ingester-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "EDITORIAL_UI_BASE_URL": "http://editor.url/",
            "NOTIFY_EDITORIAL_ADDRESS": "test@notifications.service.gov.uk",
            "NOTIFY_NEW_JUDGMENT_TEMPLATE_ID": "template-id",
            "ROLLBAR_ENV": "prod",
        },
        clear=True,
    )
    def test_send_new_judgment_notification_with_no_tdr_section(self, v2_ingest, caplog: pytest.LogCaptureFixture):
        v2_ingest.metadata = {}
        v2_ingest.uri = "d-444"
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=d-444",
            "consignment": "unknown",
            "submitter": "unknown, unknown <unknown>",
            "submitted_at": "unknown",
            "doctype": "judgment",
            "update_metadata": NULL_UPDATE_METADATA,
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_new_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )
        assert_log_has_message_starting(caplog, "Sent new notification to test@notifications.service.gov.uk")

    @patch.dict(
        os.environ,
        {"ROLLBAR_ENV": "staging"},
        clear=True,
    )
    def test_do_not_send_new_judgment_notification_on_staging(self, v2_ingest):
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_new_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_not_called()

    @patch.dict(
        os.environ,
        {
            "NOTIFY_API_KEY": "ingester-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "EDITORIAL_UI_BASE_URL": "http://editor.url/",
            "NOTIFY_EDITORIAL_ADDRESS": "test@notifications.service.gov.uk",
            "NOTIFY_UPDATED_JUDGMENT_TEMPLATE_ID": "template-id",
            "ROLLBAR_ENV": "prod",
        },
        clear=True,
    )
    def test_send_updated_judgment_notification(self, v2_ingest, caplog: pytest.LogCaptureFixture):
        v2_ingest.uri = "uri"
        v2_ingest.metadata = {
            "parameters": {
                "TDR": {
                    "Source-Organization": "Ministry of Justice",
                    "Contact-Name": "Tom King",
                    "Internal-Sender-Identifier": "TDR-2021-CF6L",
                    "Consignment-Completed-Datetime": "2021-12-16T14:54:06Z",
                    "Contact-Email": "someone@example.com",
                    "Judgment-Update": True,
                    "Judgment-Update-Type": "judgment",
                    "Judgment-Update-Details": "details",
                    "Judgment-Neutral-Citation": "[2019] UKSC 1701",
                    "Judgment-No-Neutral-Citation": False,
                    "Judgment-Reference": "Case 1",
                },
            },
        }
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=uri",
            "consignment": "TDR-2021-CF6L",
            "submitter": "Tom King, Ministry of Justice <someone@example.com>",
            "submitted_at": "2021-12-16T14:54:06Z",
            "update_metadata": '{\n  "Judgment-Update": true,\n  "Judgment-Update-Type": "judgment",\n  "Judgment-Update-Details": "details",\n  "Judgment-Neutral-Citation": "[2019] UKSC 1701",\n  "Judgment-No-Neutral-Citation": false,\n  "Judgment-Reference": "Case 1"\n}',
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_updated_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )

        assert_log_has_message_starting(caplog, "Sent update notification to test@notifications.service.gov.uk")

    @patch.dict(
        os.environ,
        {
            "NOTIFY_API_KEY": "ingester-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "EDITORIAL_UI_BASE_URL": "http://editor.url/",
            "NOTIFY_EDITORIAL_ADDRESS": "test@notifications.service.gov.uk",
            "NOTIFY_UPDATED_JUDGMENT_TEMPLATE_ID": "template-id",
            "ROLLBAR_ENV": "prod",
        },
        clear=True,
    )
    def test_send_updated_judgment_notification_with_no_tdr_section(self, v2_ingest, caplog: pytest.LogCaptureFixture):
        v2_ingest.metadata = {}
        v2_ingest.uri = "uri"
        expected_personalisation = {
            "url": "http://editor.url/detail?judgment_uri=uri",
            "consignment": "unknown",
            "submitter": "unknown, unknown <unknown>",
            "submitted_at": "unknown",
            "update_metadata": NULL_UPDATE_METADATA,
        }
        NotificationsAPIClient.send_email_notification = MagicMock()
        v2_ingest.send_updated_judgment_notification()
        NotificationsAPIClient.send_email_notification.assert_called_with(
            email_address="test@notifications.service.gov.uk",
            template_id="template-id",
            personalisation=expected_personalisation,
        )

        assert_log_has_message_starting(caplog, "Sent update notification to test@notifications.service.gov.uk")


@patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_updated_judgment_notification")
@patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_new_judgment_notification")
@patch("src.ds_caselaw_ingester.lambda_function.Ingest.send_bulk_judgment_notification")
class TestEmailLogic:
    def test_v2_ingest_publish_email_update(self, bulk, new, updated, v2_ingest):
        v2_ingest.exists_in_database = True

        v2_ingest.send_email()

        updated.assert_called()
        new.assert_not_called()
        bulk.assert_not_called()

    def test_v2_ingest_publish_email_insert(self, bulk, new, updated, v2_ingest):
        v2_ingest.inserted = True
        v2_ingest.updated = False

        v2_ingest.send_email()

        updated.assert_not_called()
        new.assert_called()
        bulk.assert_not_called()

    def test_fcl_ingest_no_email(self, bulk, new, updated, fcl_ingest):
        fcl_ingest.inserted = True
        fcl_ingest.updated = False
        fcl_ingest.send_email()

        updated.assert_not_called()
        new.assert_not_called()
        bulk.assert_not_called()

    @patch("src.ds_caselaw_ingester.ingester.Metadata.auto_publish", new_callable=PropertyMock)
    def test_s3_ingest_no_email_if_publish(self, mock_property, bulk, new, updated, s3_ingest):
        mock_property.return_value = True
        s3_ingest.send_email()

        updated.assert_not_called()
        new.assert_not_called()
        bulk.assert_not_called()

    @patch("src.ds_caselaw_ingester.ingester.Metadata.auto_publish", new_callable=PropertyMock)
    def test_s3_ingest_email_if_not_publish(self, mock_property, bulk, new, updated, s3_ingest):
        mock_property.return_value = False
        s3_ingest.send_email()

        updated.assert_not_called()
        new.assert_not_called()

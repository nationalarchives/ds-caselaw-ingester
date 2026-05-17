from aws_lambda_powertools.utilities.data_classes import SNSEvent, SQSEvent

from src.ds_caselaw_ingester import lambda_function

from .conftest import sqs_v2_event, v2_message_raw


class TestAllMessages:
    """Tests for the all_messages helper."""

    def test_parses_sns_event(self):
        event = {"Records": [{"Sns": {"Message": v2_message_raw}}]}
        results = lambda_function.all_messages(SNSEvent(event))
        assert len(results) == 1
        message_id, message = results[0]
        assert message_id is None
        assert message.get_consignment_reference() == "TDR-2022-DNWR"

    def test_parses_sqs_event(self):
        results = lambda_function.all_messages(SQSEvent(sqs_v2_event))
        assert len(results) == 1
        message_id, message = results[0]
        assert message_id == "msg-001"
        assert message.get_consignment_reference() == "TDR-2022-DNWR"

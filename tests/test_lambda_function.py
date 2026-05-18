import warnings
from unittest.mock import patch

import pytest

from src.ds_caselaw_ingester.lambda_function import create_api_client


class TestUseHTTPS:
    def use_https_helper(self, value):
        warnings.simplefilter("always")
        env_dict = {
            "MARKLOGIC_HOST": "test_host",
            "MARKLOGIC_USER": "test_user",
            "MARKLOGIC_PASSWORD": "test_pass",
        }
        if value is not None:
            env_dict["MARKLOGIC_USE_HTTPS"] = value

        with patch.dict("os.environ", env_dict, clear=True):  # noqa: SIM117
            with warnings.catch_warnings(record=True) as caught_warnings:
                create_api_client()
        return caught_warnings

    @pytest.mark.parametrize(
        "environment_value",
        [
            ("1"),
            ("true"),
            ("True"),
            ("TRUE"),
            ("yes"),
            ("on"),
            (""),
            (None),
        ],
    )
    @patch("src.ds_caselaw_ingester.lambda_function.MarklogicApiClient")
    def test_use_https_on(self, mock_api_client, environment_value):
        assert len(self.use_https_helper(environment_value)) == 0
        assert mock_api_client.call_args.kwargs["use_https"] is True

    @pytest.mark.parametrize(
        "environment_value",
        [
            ("0"),
            ("false"),
            ("False"),
            ("no"),
            ("off"),
        ],
    )
    @patch("src.ds_caselaw_ingester.lambda_function.MarklogicApiClient")
    def test_use_https_off(self, mock_api_client, environment_value):
        caught_warnings = self.use_https_helper(environment_value)
        assert str(caught_warnings[0].message) == "MarkLogic connection not using HTTPS. Traffic will be unencrypted."
        assert mock_api_client.call_args.kwargs["use_https"] is False

    @pytest.mark.parametrize(
        "environment_value",
        [
            ("maybe"),
            ("2"),
        ],
    )
    @patch("src.ds_caselaw_ingester.lambda_function.MarklogicApiClient")
    def test_use_https_maybe(self, mock_api_client, environment_value):
        caught_warnings = self.use_https_helper(environment_value)
        assert str(caught_warnings[0].message) == f"Unable to parse {environment_value} as boolean, defaulting to True"
        assert mock_api_client.call_args.kwargs["use_https"] is True

import logging
import os
import shutil

import pytest

TDR_TARBALL_PATH = os.path.join(
    os.path.dirname(__file__),
    "../aws_examples/s3/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
)

ERROR_TARBALL_PATH = os.path.join(
    os.path.dirname(__file__),
    "../aws_examples/s3/te-editorial-out-int/TDR-2025-CN7V.tar.gz",
)

BULK_TARBALL_PATH = os.path.join(os.path.dirname(__file__), "../aws_examples/s3/te-editorial-out-int/test3.tar.gz")


def create_fake_tdr_file(*args, **kwargs):
    shutil.copyfile(TDR_TARBALL_PATH, "/tmp/TDR-2022-DNWR.tar.gz")


def create_fake_error_file(*args, **kwargs):
    shutil.copyfile(ERROR_TARBALL_PATH, "/tmp/TDR-2025-CN7V.tar.gz")


def create_fake_bulk_file(*args, **kwargs):
    shutil.copyfile(BULK_TARBALL_PATH, "/tmp/BULK-0.tar.gz")


def assert_log_shows_successful_ingest(caplog: pytest.LogCaptureFixture):
    assert_log_has_message_starting(caplog, "Ingester Start: Consignment reference")
    assert_log_has_message_starting(caplog, "tar.gz saved locally as")
    assert_log_has_message_starting(caplog, "Ingesting document")
    assert_log_has_message_starting(caplog, "Updated judgment xml")
    assert_log_has_message_starting(caplog, "Upload Successful")
    assert_log_has_message(caplog, "Ingestion complete")

    assert_log_does_not_have_message_starting(caplog, "Invalid XML file")
    assert_log_does_not_have_message_starting(caplog, "No XML file found")


def assert_log_has_message(
    caplog: pytest.LogCaptureFixture,
    expected_message: str,
    expected_log_level: int = logging.INFO,
):
    assert any(
        record.levelno == expected_log_level and record.message == expected_message for record in caplog.records
    ), (
        f"Expected to find log message '{expected_message}' and level {logging.getLevelName(expected_log_level)} in logs but didn't find it in: \n{caplog.text}"
    )


def assert_log_has_message_starting(
    caplog: pytest.LogCaptureFixture,
    expected_message: str,
    expected_log_level: int = logging.INFO,
):
    assert any(
        record.levelno == expected_log_level and record.message.startswith(expected_message)
        for record in caplog.records
    ), (
        f"Expected to find log message starting with '{expected_message}' and level {logging.getLevelName(expected_log_level)} in logs but didn't find it in: \n{caplog.text}"
    )


def assert_log_does_not_have_message_starting(
    caplog: pytest.LogCaptureFixture,
    expected_message: str,
):
    assert all(not record.message.startswith(expected_message) for record in caplog.records), (
        f"Expected not to find log message starting with '{expected_message}' in logs but found it in: \n{caplog.text}"
    )

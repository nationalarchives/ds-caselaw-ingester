import os
import shutil

TDR_TARBALL_PATH = os.path.join(
    os.path.dirname(__file__),
    "../aws_examples/s3/te-editorial-out-int/TDR-2022-DNWR.tar.gz",
)

BULK_TARBALL_PATH = os.path.join(os.path.dirname(__file__), "../aws_examples/s3/te-editorial-out-int/test3.tar.gz")


def create_fake_tdr_file(*args, **kwargs):
    shutil.copyfile(TDR_TARBALL_PATH, "/tmp/TDR-2022-DNWR.tar.gz")


def create_fake_bulk_file(*args, **kwargs):
    shutil.copyfile(BULK_TARBALL_PATH, "/tmp/BULK-0.tar.gz")

def test_fixture_load(v2_ingest, s3_ingest):
    """We get the XML of the data and extract the URI from it successfully using the fixtures"""

    assert v2_ingest.uri == "d-v2-a1b2-c3d4"
    assert s3_ingest.uri == "d-s3-a1b2-c3d4"

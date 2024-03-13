from unittest.mock import ANY, PropertyMock, patch

import pytest
from lambda_function import (
    ErrorLogWouldOverwritePublishedDocument,
    TarWrapper,
    parse_xml,
)

akoma = (
    "<akomaNtoso "
    'xmlns="http://docs.oasis-open.org/legaldocml/ns/akn/3.0" '
    'xmlns:html="http://www.w3.org/1999/xhtml" '
    'xmlns:uk="https://caselaw.nationalarchives.gov.uk/akn"/>'
)


@patch(
    "lambda_function.TarWrapper.best_xml",
    new_callable=PropertyMock,
    return_value=parse_xml("<error/>"),
)
@patch(
    "lambda_function.TarWrapper.target_document_published",
    new_callable=PropertyMock,
    return_value=True,
)
@patch("lambda_function.TarWrapper.uri", new_callable=PropertyMock, return_value="uri")
def test_verify_xml_error_pub(uri, doc, xml):
    wrapped_tar = TarWrapper(None)

    with pytest.raises(ErrorLogWouldOverwritePublishedDocument):
        wrapped_tar.verify_xml_is_writable()


@patch(
    "lambda_function.TarWrapper.best_xml",
    new_callable=PropertyMock,
    return_value=parse_xml(akoma),
)
@patch(
    "lambda_function.TarWrapper.target_document_published",
    new_callable=PropertyMock,
    return_value=True,
)
@patch("lambda_function.TarWrapper.uri", new_callable=PropertyMock, return_value="uri")
def test_verify_xml_akoma_pub(uri, doc, xml):
    wrapped_tar = TarWrapper(None)
    assert wrapped_tar.verify_xml_is_writable()


@patch(
    "lambda_function.TarWrapper.best_xml",
    new_callable=PropertyMock,
    return_value=parse_xml("<error/>"),
)
@patch(
    "lambda_function.TarWrapper.target_document_published",
    new_callable=PropertyMock,
    return_value=False,
)
@patch("lambda_function.TarWrapper.uri", new_callable=PropertyMock, return_value="uri")
def test_verify_xml_error_unpub(uri, doc, xml):
    wrapped_tar = TarWrapper(None)
    assert wrapped_tar.verify_xml_is_writable()


@patch(
    "lambda_function.TarWrapper.best_xml",
    new_callable=PropertyMock,
    return_value=parse_xml(akoma),
)
@patch(
    "lambda_function.TarWrapper.target_document_published",
    new_callable=PropertyMock,
    return_value=False,
)
@patch("lambda_function.TarWrapper.uri", new_callable=PropertyMock, return_value="uri")
def test_verify_xml_akoma_unpub(uri, doc, xml):
    wrapped_tar = TarWrapper(None)
    assert wrapped_tar.verify_xml_is_writable()


###################


@patch(
    "lambda_function.TarWrapper.best_xml",
    new_callable=PropertyMock,
    return_value=parse_xml(akoma),
)
@patch(
    "lambda_function.TarWrapper.target_document_published",
    new_callable=PropertyMock,
    return_value=True,
)
@patch("lambda_function.TarWrapper.uri", new_callable=PropertyMock, return_value="uri")
@patch("lambda_function.api_client")
@patch("lambda_function.update_published_documents")
@patch("lambda_function.get_aws_clients", return_value=(None, None))
@patch("lambda_function.TarWrapper.metadata", new_callable=PropertyMock)
def test_no_publish_if_not_forced(metadata, aws, update, api_client, uri, doc, xml):
    wrapped_tar = TarWrapper(None)
    api_client.get_published.return_value = True
    metadata.force_publish.return_value = False
    wrapped_tar.publish_if_appropriate()
    api_client.set_published.assert_called_with("uri", True)
    update.assert_called_with("uri", ANY)


@patch(
    "lambda_function.TarWrapper.best_xml",
    new_callable=PropertyMock,
    return_value=parse_xml(akoma),
)
@patch(
    "lambda_function.TarWrapper.target_document_published",
    new_callable=PropertyMock,
    return_value=True,
)
@patch("lambda_function.TarWrapper.uri", new_callable=PropertyMock, return_value="uri")
@patch("lambda_function.api_client")
@patch("lambda_function.update_published_documents")
@patch("lambda_function.get_aws_clients", return_value=(None, None))
@patch("lambda_function.TarWrapper.metadata", new_callable=PropertyMock)
def test_publish_if_force_and_akoma(metadata, aws, update, api_client, uri, doc, xml):
    wrapped_tar = TarWrapper(None)
    api_client.get_published.return_value = True
    metadata.force_publish.return_value = True
    wrapped_tar.publish_if_appropriate()
    api_client.set_published.assert_called_with("uri", True)
    update.assert_called_with("uri", ANY)


@patch(
    "lambda_function.TarWrapper.best_xml",
    new_callable=PropertyMock,
    return_value=parse_xml("<error/>"),
)
@patch(
    "lambda_function.TarWrapper.target_document_published",
    new_callable=PropertyMock,
    return_value=True,
)
@patch("lambda_function.TarWrapper.uri", new_callable=PropertyMock, return_value="uri")
@patch("lambda_function.api_client")
@patch("lambda_function.update_published_documents")
@patch("lambda_function.get_aws_clients", return_value=(None, None))
@patch("lambda_function.TarWrapper.metadata", new_callable=PropertyMock)
def test_no_publish_if_error(metadata, aws, update, api_client, uri, doc, xml):
    # It never even checks if the document is published or not.
    wrapped_tar = TarWrapper(None)
    metadata.force_publish.return_value = True
    wrapped_tar.publish_if_appropriate()
    api_client.set_published.assert_not_called()
    api_client.get_published.assert_not_called()
    update.assert_not_called()

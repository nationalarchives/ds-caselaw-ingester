class IngestionError(Exception):
    """A known, non-transient ingestion failure (e.g. bad XML, unknown court).

    Retrying these at the AWS level will not help — the underlying document or
    message is fundamentally broken. Subclass this for specific failure modes so
    they show up with meaningful names in Rollbar and tracebacks.
    """


class S3HTTPError(IngestionError):
    pass


class MaximumRetriesExceededException(IngestionError):
    pass


class InvalidXMLException(IngestionError):
    pass


class InvalidMessageException(IngestionError):
    pass


class ErrorLogWouldOverwritePublishedDocument(IngestionError):
    pass


class FileNotFoundException(IngestionError):
    pass


class DocxFilenameNotFoundException(IngestionError):
    pass


class DocumentInsertionError(IngestionError):
    pass


class MultipleResolutionsFoundError(DocumentInsertionError):
    pass


class DocumentXMLNotYetInDatabase(IngestionError):
    pass


class CannotPublishException(IngestionError):
    pass

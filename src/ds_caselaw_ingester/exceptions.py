class ReportableException(Exception):
    pass


class S3HTTPError(ReportableException):
    pass


class MaximumRetriesExceededException(ReportableException):
    pass


class InvalidXMLException(ReportableException):
    pass


class InvalidMessageException(ReportableException):
    pass


class ErrorLogWouldOverwritePublishedDocument(ReportableException):
    pass


class FileNotFoundException(ReportableException):
    pass


class DocxFilenameNotFoundException(ReportableException):
    pass


class DocumentInsertionError(ReportableException):
    pass


class MultipleResolutionsFoundError(DocumentInsertionError):
    pass


class DocumentXMLNotYetInDatabase(ReportableException):
    pass


class CannotPublishException(ReportableException):
    pass

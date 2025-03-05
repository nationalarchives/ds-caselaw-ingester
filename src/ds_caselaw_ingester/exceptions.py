import rollbar


class ReportableException(Exception):
    def __init__(self, *args, **kwargs) -> None:
        rollbar.report_message("Something happened!", "warning", str(self))
        super().__init__(*args, **kwargs)


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

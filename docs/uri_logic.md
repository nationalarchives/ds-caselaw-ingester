# URI resolution/generation logic

This flowchart explains the logic followed by the ingester to find the correct URI and insert/update path for a document.

This process is called as part of the `__init__()` method on `Ingest` objects

```mermaid
flowchart TD

    INIT([Initialise new Ingest object])

    INIT --> URI_IN_PARSER_METADATA

    URI_IN_PARSER_METADATA{Is a URI present in the parser metadata?}

    URI_IN_PARSER_METADATA -- Yes --> EXISTING_DOCUMENT_AT_URI

    EXISTING_DOCUMENT_AT_URI{Is there a document in MarkLogic at that URL?}

    EXISTING_DOCUMENT_AT_URI -- Yes --> SET_URI_TO_EXISTING_DOC

    URI_IN_PARSER_METADATA -- No --> NCN_IN_PARSER_METADATA
    EXISTING_DOCUMENT_AT_URI -- No --> NCN_IN_PARSER_METADATA

    NCN_IN_PARSER_METADATA{Is an NCN present in the Parser metadata?}

    NCN_IN_PARSER_METADATA -- Yes --> FIND_DOCUMENT_ID_SCHEMA

    FIND_DOCUMENT_ID_SCHEMA[Find correct ID schema for document]

    FIND_DOCUMENT_ID_SCHEMA --> EXISTING_DOCUMENT_AT_NCN

    EXISTING_DOCUMENT_AT_NCN{Is there an existing document in MarkLogic with matching NCN and schema?}

    EXISTING_DOCUMENT_AT_NCN -- Yes --> SET_URI_TO_EXISTING_DOC

    SET_URI_TO_EXISTING_DOC(["Return a tuple of (uri=existing document URI, exists=True)"])

    NCN_IN_PARSER_METADATA -- No --> GENERATE_UUID_URI

    EXISTING_DOCUMENT_AT_NCN -- No --> GENERATE_UUID_URI

    GENERATE_UUID_URI[Generate new UUID-based URI]
    GENERATE_UUID_URI --> SET_URI_TO_UUID
    SET_URI_TO_UUID(["Return a tuple of (uri=new UUID URI, exists=False)"])

```

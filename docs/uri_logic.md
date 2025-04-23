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



    URI_IN_PARSER_METADATA -- No --> DOCUMENT_HAS_NCN
    EXISTING_DOCUMENT_AT_URI -- No --> DOCUMENT_HAS_NCN

    DOCUMENT_HAS_NCN{Is there an existing document in MarkLogic with the NCN present in the Parser metadata?}

    DOCUMENT_HAS_NCN -- Yes --> EXISTING_DOCUMENT_AT_NCN

    EXISTING_DOCUMENT_AT_NCN{Is there an NCN present in the Parser metadata?}

    EXISTING_DOCUMENT_AT_NCN -- Yes --> SET_URI_TO_EXISTING_DOC

    SET_URI_TO_EXISTING_DOC(["Return a tuple of (uri=existing document URI, exists=True)"])

    DOCUMENT_HAS_NCN -- No --> GENERATE_UUID_URI

    EXISTING_DOCUMENT_AT_NCN -- No --> GENERATE_UUID_URI

    GENERATE_UUID_URI[Generate new UUID-based URI]
    GENERATE_UUID_URI --> SET_URI_TO_UUID
    SET_URI_TO_UUID(["Return a tuple of (uri=new UUID URI, exists=False)"])

```

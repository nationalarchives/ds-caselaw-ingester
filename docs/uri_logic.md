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

    SET_URI_TO_EXISTING_DOC --> TOGGLE_UPDATE_STATE

    TOGGLE_UPDATE_STATE@{ shape: win-pane, label: "Record document as being an in-place update" }

    URI_IN_PARSER_METADATA -- No --> DOCUMENT_HAS_NCN
    EXISTING_DOCUMENT_AT_URI -- No --> DOCUMENT_HAS_NCN

    DOCUMENT_HAS_NCN{Is there an NCN present in the Parser metadata?}

    DOCUMENT_HAS_NCN -- Yes --> EXISTING_DOCUMENT_AT_NCN

    EXISTING_DOCUMENT_AT_NCN{Is there an existing document in MarkLogic with that NCN in the relevant identifier scheme?}

    EXISTING_DOCUMENT_AT_NCN -- Yes --> SET_URI_TO_EXISTING_DOC

    SET_URI_TO_EXISTING_DOC@{ shape: win-pane, label: "Set document URI to URI of existing document" }

    DOCUMENT_HAS_NCN -- No --> GENERATE_UUID_URI

    GENERATE_NCN_URI[Generate new NCN-based URI]
    GENERATE_NCN_URI --> SET_URI_TO_NCN
    SET_URI_TO_NCN@{ shape: win-pane, label: "Set document URI to new NCN-based URI" }
    SET_URI_TO_NCN --> TOGGLE_INSERT_STATE

    EXISTING_DOCUMENT_AT_NCN -- No --> GENERATE_NCN_URI

    GENERATE_UUID_URI[Generate new UUID-based URI]
    GENERATE_UUID_URI --> SET_URI_TO_UUID
    SET_URI_TO_UUID@{ shape: win-pane, label: "Set document URI to new UUID-based URI" }

    SET_URI_TO_UUID --> TOGGLE_INSERT_STATE
    TOGGLE_INSERT_STATE@{ shape: win-pane, label: "Record document as being an insert" }

    TOGGLE_UPDATE_STATE --> RETURN
    TOGGLE_INSERT_STATE --> RETURN

    RETURN(["Return a tuple of (URI, update/insert)"])
```

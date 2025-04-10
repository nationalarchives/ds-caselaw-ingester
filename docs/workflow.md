# Ingestion workflow

This describes the sequence of events which happens when a document is ingested.

```mermaid

sequenceDiagram
    participant SNS as Amazon SNS
    participant lambda as lambda_function
    participant perform_ingest

    activate SNS
    SNS ->> lambda : SNS Event
    deactivate SNS

    activate lambda

    lambda ->> lambda : Unpack event to list of Messages

    loop for each Message

        create participant Ingest
        lambda ->> Ingest : Create new Ingest instance
        note right of Ingest: __init__() on Ingest does the work of downloading and<br>establishing facts about the incoming document.
        activate Ingest

        Ingest ->> Ingest : Assign internal variables based on message contents

        participant S3 as Amazon S3

        Ingest <<->> S3 : Download consignment .tar.gz
        Ingest ->> Ingest : Unpack .tar.gz to local filesystem
        Ingest ->> Ingest : Extract metadata from JSON blob
        Ingest ->> Ingest : Get document XML
        Ingest ->> Ingest : Determine document URI and presence of existing document
        Ingest ->> lambda : Return Ingest object

        deactivate Ingest

        lambda ->> perform_ingest : perform_ingest(Ingest)
        note right of perform_ingest: This is where we actually start to insert or update things.<br>perform_ingest() orchestrates the operations.

        perform_ingest ->>+ Ingest: insert_or_update_xml()
        deactivate Ingest

        perform_ingest ->>+ Ingest: set_document_identifiers()
        deactivate Ingest

        perform_ingest ->>+ Ingest: send_email()
        deactivate Ingest

        opt If TDR parameters present
            perform_ingest ->>+ Ingest: store_metadata()
            Ingest ->> MarkLogic : Set document metadata properties
            deactivate Ingest
        end

        perform_ingest ->>+ Ingest: save_files_to_s3()
        deactivate Ingest

        alt Document is set to auto-publish
            perform_ingest ->>+ Ingest: document.publish()
            perform_ingest ->> Ingest: update_published_documents()
            Ingest <<->> S3 : Get list of assets with document prefix
            loop For each asset
                Ingest ->> S3 : Copy asset to published bucket
            end
            deactivate Ingest
        else Document is not set to auto-publish
            perform_ingest ->>+ Ingest: document.unpublish()
            deactivate Ingest
        end

    end

    deactivate lambda

```

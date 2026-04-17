# Deployment

<!-- last_review: 2026-04-14 -->

This project has two separately deployed components:

| Component                | Tool      | Config         |
| ------------------------ | --------- | -------------- |
| Lambda function          | SAM       | `template.yml` |
| SQS queue infrastructure | Terraform | `terraform/`   |

Both are deployed automatically via GitHub Actions. The deploy workflows call Terraform first, then SAM, ensuring infrastructure is in place before the Lambda is updated.

## Environments

### Staging

Every push to `main` deploys both components to the staging environment (`deploy.yml`).

### Production

Creating a tagged release deploys both components to production (`deploy-production.yml`). See the [release process](../README.md#release-process).

## Lambda (SAM)

The Lambda function is defined in `template.yml` and deployed using [AWS SAM](https://docs.aws.amazon.com/serverless-application-model/).

The deploy workflows run:

```bash
sam build --use-container -m requirements/base.txt
sam deploy --parameter-overrides ...
```

Environment-specific parameters (secrets, VPC config, queue ARNs, etc.) are stored as GitHub environment variables and secrets.

## Terraform (SQS infrastructure)

The `terraform/` directory defines the SQS ingest queue and dead-letter queue that sit between the SNS topic(s) and the Lambda. These are deployed using the shared [`da-terraform-modules//sqs`](https://github.com/nationalarchives/da-terraform-modules/tree/main/sqs) module.

### Manual dispatch

You can plan or apply Terraform manually via **Actions → Terraform Plan and Apply**:

1. Select the target **environment** (`staging` or `production`).
2. Set **apply** to `true` to apply (defaults to `false` for plan-only).
3. Click **Run workflow**.

### Running Terraform locally

```bash
cd terraform
terraform init -backend-config="bucket=<your-state-bucket>"
terraform plan
terraform apply
```

#### Required variables

Set via `TF_VAR_*` environment variables or `-var`:

| Variable         | Description                                 |
| ---------------- | ------------------------------------------- |
| `environment`    | Environment name (`staging`, `production`)  |
| `sns_topic_arns` | JSON list of SNS topic ARNs to subscribe to |

All other variables have sensible defaults. See `terraform/variables.tf` for the full list.

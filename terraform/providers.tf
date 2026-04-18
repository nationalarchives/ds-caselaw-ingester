terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Backend bucket is provided at init time via:
  #   terraform init -backend-config="bucket=<bucket-name>"
  # CI passes this from the TF_BACKEND_BUCKET secret.
  backend "s3" {
    key    = "ds-caselaw-ingester/terraform.tfstate"
    region = "eu-west-2"
  }
}

provider "aws" {
  region = var.aws_region
}

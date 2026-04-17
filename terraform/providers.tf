terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend configuration should be provided per-environment.
  # Example for S3 backend:
  # backend "s3" {
  #   bucket = "my-terraform-state"
  #   key    = "ds-caselaw-ingester/terraform.tfstate"
  #   region = "eu-west-2"
  # }
}

provider "aws" {
  region = var.aws_region
}

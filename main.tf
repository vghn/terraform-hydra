terraform {
  required_version = ">= 0.12"
  backend "remote" {
    organization = "vgh"
    workspaces {
      name = "hydra"
    }
  }
}

locals {
  common_tags = {
    Terraform = "true"
    Group     = "vgh"
    Project   = "vault"
  }
}

provider "aws" {
  region  = "us-east-1"
  version = "~> 2.0"
}

provider "cloudflare" {
  version = "~> 2.0"
  email   = var.cloudflare_email
  api_key = var.cloudflare_api_key
}

provider "null" {
  version = "~> 2.0"
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

module "notifications" {
  source = "github.com/vghn/terraform-notifications"

  email = var.email

  common_tags = var.common_tags
}

module "billing" {
  source = "github.com/vghn/terraform-billing"

  notifications_topic_arn = module.notifications.topic_arn
  thresholds              = ["1", "2", "3", "4", "5"]
  account                 = "Hydra"

  common_tags = var.common_tags
}

module "cloudwatch_event_watcher" {
  source = "github.com/vghn/terraform-cloudwatch_event_watcher"

  common_tags = var.common_tags
}

module "cloudtrail" {
  source = "github.com/vghn/terraform-cloudtrail"

  common_tags = var.common_tags
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 2.0"

  name = "VGH"
  cidr = "10.0.0.0/16"

  enable_dns_support   = true
  enable_dns_hostnames = true

  azs = [
    "us-east-1a",
    "us-east-1b",
    "us-east-1c",
    "us-east-1d",
    "us-east-1e",
    "us-east-1f",
  ]

  public_subnets = [
    "10.0.1.0/24",
    "10.0.2.0/24",
    "10.0.3.0/24",
    "10.0.4.0/24",
    "10.0.5.0/24",
    "10.0.6.0/24",
  ]

  tags = var.common_tags
}

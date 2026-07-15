# Minimal root config for a Myrmex Hive gateway on AWS.
#
#   terraform init && terraform apply
#   terraform output -raw host_public_key   # pin this in agent_config.json
#
# This costs money (one EC2 instance). `terraform destroy` removes everything
# EXCEPT the SSM host-key parameter, which is prevent_destroy — it signs the
# audit log, so losing it makes past entries unverifiable.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

module "gateway" {
  source = "../../modules/aws-gateway"

  name            = "myrmex-gateway"
  gateway_version = "1.0.3"

  vpc_id    = var.vpc_id
  subnet_id = var.subnet_id

  # Agents dial OUT to :2222 — scope this to where they actually live.
  agent_cidrs = var.agent_cidrs
  # The operator control plane. The module rejects 0.0.0.0/0 here.
  operator_cidrs = var.operator_cidrs

  # agent_id => public key. The module rewrites each key's comment to the
  # agent_id, which is what the gateway binds the identity to.
  agent_public_keys = var.agent_public_keys

  auth_token = var.auth_token

  # Anything from pkg/config.GatewayConfig. Metrics are opt-in.
  gateway_config_extra = {
    metrics_enabled      = true
    metrics_poll_seconds = 30
    alert_thresholds = {
      cpu_percent  = 90
      mem_percent  = 90
      disk_percent = 85
    }
  }

  tags = {
    Environment = "demo"
  }
}

# Myrmex Hive gateway on AWS (#105).
#
# Shape follows the product's security model rather than a generic web-server
# module: agents dial OUT to :2222, operators reach :8080, and the target
# machines never listen. So the only inbound rules are those two, each scoped to
# a caller-supplied CIDR.
#
# Secrets (config, host key, authorized_keys) live in SSM SecureString and are
# fetched by the instance at boot via an IAM role — they are never baked into
# the AMI or passed through user_data, which is world-readable from within the
# instance via IMDS.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0"
    }
  }
}

locals {
  # The gateway derives each agent's identity from the authorized_keys COMMENT
  # and rejects a mismatch. Building the line here — key type + material from
  # the map value, comment forced to the map key — makes that correct by
  # construction instead of a documented footgun.
  authorized_keys = join("\n", [
    for agent_id, key in var.agent_public_keys :
    format("%s %s %s", split(" ", trimspace(key))[0], split(" ", trimspace(key))[1], agent_id)
  ])

  host_private_key = var.host_private_key != null ? var.host_private_key : tls_private_key.host[0].private_key_openssh

  # Conditioned on the resource count, NOT on var.host_private_key: referencing
  # that sensitive variable in the condition taints this whole expression as
  # sensitive, and Terraform then refuses to output it. A PUBLIC key is not a
  # secret — operators must copy it into agent configs — so the taint would be
  # wrong, and marking the output sensitive would just hide something people
  # need.
  host_public_key = length(tls_private_key.host) > 0 ? tls_private_key.host[0].public_key_openssh : null

  gateway_config = merge({
    listen_addr          = ":2222"
    http_addr            = ":8080"
    host_key_path        = "/etc/myrmex/host_key"
    authorized_keys_path = "/etc/myrmex/authorized_keys"
    audit_log_path       = "/var/lib/myrmex/audit.log"
    auth_token           = var.auth_token
  }, var.gateway_config_extra)

  tags = merge({ "app.kubernetes.io/name" = "myrmex-hive" }, var.tags)
}

# Generated only when the caller does not supply one. Ed25519 to match the rest
# of the product.
resource "tls_private_key" "host" {
  count     = var.host_private_key == null ? 1 : 0
  algorithm = "ED25519"
}

# --- Secrets -----------------------------------------------------------------

resource "aws_ssm_parameter" "host_key" {
  name        = "/${var.name}/host_key"
  description = "Gateway SSH host key. Signs the audit log — replacing it invalidates every past signature."
  type        = "SecureString"
  value       = local.host_private_key
  tags        = local.tags

  lifecycle {
    # The audit chain is only verifiable while this key survives. Destroying it
    # is almost never what you want; remove this block deliberately if it is.
    prevent_destroy = true
  }
}

resource "aws_ssm_parameter" "authorized_keys" {
  name        = "/${var.name}/authorized_keys"
  description = "Agent allowlist. Comment on each line is the agent_id the gateway binds the key to."
  type        = "SecureString"
  value       = local.authorized_keys
  tags        = local.tags
}

resource "aws_ssm_parameter" "gateway_config" {
  name        = "/${var.name}/gateway_config.json"
  description = "gateway_config.json. SecureString because it carries auth_token/tokens/llm_api_key."
  type        = "SecureString"
  value       = jsonencode(local.gateway_config)
  tags        = local.tags
}

# --- Networking --------------------------------------------------------------

resource "aws_security_group" "gateway" {
  name        = var.name
  description = "Myrmex Hive gateway: agent tunnel in on 2222, operator API in on 8080"
  vpc_id      = var.vpc_id
  tags        = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "agent_tunnel" {
  for_each = toset(var.agent_cidrs)

  security_group_id = aws_security_group.gateway.id
  description       = "Agent SSH tunnel (agents dial out to here)"
  cidr_ipv4         = each.value
  from_port         = 2222
  to_port           = 2222
  ip_protocol       = "tcp"
  tags              = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "operator_api" {
  for_each = toset(var.operator_cidrs)

  security_group_id = aws_security_group.gateway.id
  description       = "Operator HTTPS API/portal"
  cidr_ipv4         = each.value
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
  tags              = local.tags
}

# Outbound is required: pulling the image, and any LLM/upstream MCP calls.
resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.gateway.id
  description       = "Image pull, LLM/upstream MCP calls"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  tags              = local.tags
}

# --- Instance role: read its own secrets, nothing else ------------------------

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "ssm_read" {
  statement {
    actions = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = [
      aws_ssm_parameter.host_key.arn,
      aws_ssm_parameter.authorized_keys.arn,
      aws_ssm_parameter.gateway_config.arn,
    ]
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${data.aws_region.current.region}.amazonaws.com"]
    }
  }
}

data "aws_region" "current" {}

resource "aws_iam_role" "gateway" {
  name               = var.name
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "ssm_read" {
  name   = "${var.name}-ssm-read"
  role   = aws_iam_role.gateway.id
  policy = data.aws_iam_policy_document.ssm_read.json
}

resource "aws_iam_instance_profile" "gateway" {
  name = var.name
  role = aws_iam_role.gateway.name
  tags = local.tags
}

# --- Instance ----------------------------------------------------------------

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_instance" "gateway" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.gateway.id]
  iam_instance_profile   = aws_iam_instance_profile.gateway.name

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    name            = var.name
    gateway_version = var.gateway_version
    region          = data.aws_region.current.region
  })
  # Re-run user_data (and so pick up a new version) when it changes.
  user_data_replace_on_change = true

  metadata_options {
    # IMDSv2 only: the instance role can read the gateway's secrets, so a
    # server-side request forgery reaching IMDSv1 would hand them over.
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    encrypted = true
  }

  tags = merge(local.tags, { Name = var.name })

  depends_on = [
    aws_ssm_parameter.host_key,
    aws_ssm_parameter.authorized_keys,
    aws_ssm_parameter.gateway_config,
  ]
}

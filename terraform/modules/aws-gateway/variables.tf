variable "name" {
  description = "Name prefix for all created resources."
  type        = string
  default     = "myrmex-gateway"
}

variable "gateway_version" {
  description = <<-EOT
    Myrmex Hive version to run, used as the container tag. Pin it; "latest"
    moves on every release. Images are cosign-signed from 1.0.3 onward.
  EOT
  type        = string
  default     = "1.0.3"
}

variable "agent_public_keys" {
  description = <<-EOT
    Agents allowed to connect, as agent_id => SSH public key.

    Pass the key WITHOUT a comment (or with any comment) — the module rewrites
    the comment to the map key. The gateway takes each agent's identity from
    that comment and rejects a key whose comment does not match the agent_id
    the agent presents, so building the line here removes the single most
    common way to misconfigure this.

    Example:
      { "web-1" = "ssh-ed25519 AAAAC3Nza..." }
  EOT
  type        = map(string)

  validation {
    condition     = length(var.agent_public_keys) > 0
    error_message = "At least one agent key is required: the gateway refuses to start without an agent allowlist."
  }

  validation {
    condition = alltrue([
      for k in values(var.agent_public_keys) : can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9-]+) [A-Za-z0-9+/=]+", trimspace(k)))
    ])
    error_message = "Each value must be an OpenSSH public key line, e.g. \"ssh-ed25519 AAAAC3Nza...\"."
  }

  validation {
    condition     = alltrue([for k in keys(var.agent_public_keys) : can(regex("^[A-Za-z0-9._-]+$", k))])
    error_message = "Agent IDs are used as the authorized_keys comment; keep them to [A-Za-z0-9._-]."
  }
}

variable "agent_cidrs" {
  description = <<-EOT
    CIDRs allowed to reach the SSH tunnel port (2222). Agents dial OUT to the
    gateway, so this is the only inbound path they need — scope it to where
    your agents live, not 0.0.0.0/0.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.agent_cidrs) > 0
    error_message = "At least one agent CIDR is required, or no agent can connect."
  }
}

variable "operator_cidrs" {
  description = <<-EOT
    CIDRs allowed to reach the HTTPS API/portal (8080). This is the operator
    control plane — keep it tight (VPN/bastion), never 0.0.0.0/0.
  EOT
  type        = list(string)

  validation {
    condition     = !contains(var.operator_cidrs, "0.0.0.0/0")
    error_message = "Refusing 0.0.0.0/0 for the operator control plane. Put it behind a VPN, bastion or ALB with auth."
  }
}

variable "subnet_id" {
  description = "Subnet to launch the gateway in. Needs a route to the internet to pull the image."
  type        = string
}

variable "vpc_id" {
  description = "VPC the security group is created in. Must contain subnet_id."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type."
  type        = string
  default     = "t3.small"
}

variable "auth_token" {
  description = <<-EOT
    Admin bearer token for the gateway API. Stored in SSM as a SecureString.

    NOTE: this value lands in Terraform state. Use an encrypted remote backend,
    or set it to null and write the SSM parameter out of band.
  EOT
  type        = string
  sensitive   = true
  default     = null
}

variable "host_private_key" {
  description = <<-EOT
    PEM-encoded Ed25519 SSH host key. Leave null to have the module generate
    one.

    This key signs the audit log, so it MUST be stable: replacing it makes every
    previously signed entry unverifiable. The module stores it in SSM and marks
    the parameter with prevent_destroy for that reason. Supply your own if you
    want it managed outside Terraform state.
  EOT
  type        = string
  sensitive   = true
  default     = null
}

variable "gateway_config_extra" {
  description = <<-EOT
    Extra keys merged verbatim into gateway_config.json — e.g. metrics_enabled,
    alert_thresholds, tracing_enabled, scoped_tokens. See pkg/config.GatewayConfig.
  EOT
  type        = any
  default     = {}
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}

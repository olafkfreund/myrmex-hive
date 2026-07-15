variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  description = "Public subnet — the gateway needs to pull its image."
  type        = string
}

variable "agent_cidrs" {
  description = "Where your agents dial from."
  type        = list(string)
}

variable "operator_cidrs" {
  description = "Your VPN/bastion. The module refuses 0.0.0.0/0."
  type        = list(string)
}

variable "agent_public_keys" {
  description = "agent_id => SSH public key."
  type        = map(string)
}

variable "auth_token" {
  description = "Admin bearer token. Lands in Terraform state — use an encrypted remote backend."
  type        = string
  sensitive   = true
}

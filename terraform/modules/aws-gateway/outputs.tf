output "gateway_addr" {
  description = "Address agents dial. Put this in agent_config.json's gateway_addr."
  value       = "${aws_instance.gateway.public_ip}:2222"
}

output "api_url" {
  description = <<-EOT
    Operator API/portal. HTTPS with a self-signed certificate regenerated on
    every restart unless tls_cert_path/tls_key_path are configured — expect to
    pass -k until you front this with a real certificate.
  EOT
  value       = "https://${aws_instance.gateway.public_ip}:8080"
}

output "host_public_key" {
  description = <<-EOT
    The gateway's SSH host public key, when the module generated it.

    Agents default to trust-on-first-use. Pin this instead by setting
    gateway_host_key in agent_config.json — TOFU is only safe if the first
    connection is.

    null when you supplied host_private_key: derive the public half yourself
    with `ssh-keygen -y -f <key>`.
  EOT
  value       = local.host_public_key
}

output "agent_config" {
  description = <<-EOT
    Ready-to-use agent_config.json fragments, keyed by agent_id — the
    enrollment info agents need. Each pins the gateway host key rather than
    relying on TOFU.

    Merge with the agent's private_key_path and allowed_commands.
  EOT
  value = {
    for agent_id in keys(var.agent_public_keys) : agent_id => {
      agent_id         = agent_id
      gateway_addr     = "${aws_instance.gateway.public_ip}:2222"
      gateway_host_key = local.host_public_key
    }
  }
}

output "instance_id" {
  description = "EC2 instance ID, for SSM Session Manager access."
  value       = aws_instance.gateway.id
}

output "security_group_id" {
  description = "Security group ID, e.g. to attach further rules."
  value       = aws_security_group.gateway.id
}

output "ssm_parameter_names" {
  description = "SSM parameters holding the gateway's secrets."
  value = {
    host_key        = aws_ssm_parameter.host_key.name
    authorized_keys = aws_ssm_parameter.authorized_keys.name
    gateway_config  = aws_ssm_parameter.gateway_config.name
  }
}

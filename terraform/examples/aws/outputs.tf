output "gateway_addr" {
  description = "Put this in each agent's gateway_addr."
  value       = module.gateway.gateway_addr
}

output "api_url" {
  description = "Operator API/portal (self-signed cert by default)."
  value       = module.gateway.api_url
}

output "host_public_key" {
  description = "Pin this as gateway_host_key in agent_config.json instead of relying on TOFU."
  value       = module.gateway.host_public_key
}

output "agent_config" {
  description = "Ready-made agent_config.json fragments, keyed by agent_id."
  value       = module.gateway.agent_config
}

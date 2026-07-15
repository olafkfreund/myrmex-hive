# Terraform: Myrmex Hive gateway on AWS

Provisions a gateway: EC2 instance, security group scoped to the two ports that
matter, secrets in SSM, and the enrollment info agents need.

Only the **gateway** is provisioned. Agents run on machines you already have —
that is the point of the product, and it is why there is no agent module.

```
terraform/
├── modules/aws-gateway/    # the module
└── examples/aws/           # a working root config
```

## Quick start

```bash
cd terraform/examples/aws
cp terraform.tfvars.example terraform.tfvars   # edit it
export TF_VAR_auth_token='...'                 # keep this out of the file
terraform init
terraform apply
```

Then wire up an agent:

```bash
terraform output -raw gateway_addr        # -> 203.0.113.5:2222
terraform output -raw host_public_key     # pin this, don't rely on TOFU
terraform output -json agent_config       # ready-made per-agent fragments
```

## What it creates

| Resource | Why |
|---|---|
| EC2 instance (AL2023) | Runs `ghcr.io/olafkfreund/myrmex-gateway` under systemd |
| Security group | **2222** from `agent_cidrs`, **8080** from `operator_cidrs`. Nothing else inbound. |
| 3× SSM SecureString | `gateway_config.json`, `host_key`, `authorized_keys` |
| IAM role + profile | Lets the instance read *only* those three parameters |

Secrets are fetched from SSM at boot, never templated into user_data — user_data
is readable from inside the instance via IMDS, so the admin token would be
sitting there for any compromised process to read. IMDSv2 is required for the
same reason.

## Three things this module gets right for you

**The `authorized_keys` comment is built, not documented.** The gateway derives
each agent's identity from the comment on its key and rejects a mismatch — the
single most common way to misconfigure this. You pass `agent_id => public key`
and the module writes the comment itself, so the failure cannot happen:

```hcl
agent_public_keys = { "web-1" = "ssh-ed25519 AAAAC3Nza..." }
# becomes: ssh-ed25519 AAAAC3Nza... web-1
```

**The host key survives instance replacement.** It signs the audit log, so a
regenerated key makes every past entry unverifiable. It lives in SSM, not on
instance disk, and the parameter is `prevent_destroy`.

**`0.0.0.0/0` on the operator port is rejected.** `:8080` is the control plane;
an open one is a gateway to every agent you manage. Front it with a VPN, a
bastion, or an authenticating ALB.

## Caveats worth reading before `apply`

- **Secrets land in Terraform state.** `auth_token` and the generated host key
  are in state and in the plan. Use an encrypted remote backend, or pass
  `auth_token = null` and write the SSM parameter out of band.
- **TLS is self-signed** and regenerated on every restart, so `curl -k` until
  you set `tls_cert_path`/`tls_key_path` via `gateway_config_extra` and mount a
  real certificate.
- **Single instance, no ASG or load balancer.** The gateway supports an HA peer
  mesh (`peer_gateways`), but wiring that up is left to you — a second `module`
  block plus `cluster_secret` and `peer_gateways` in `gateway_config_extra`.
- **Public IP.** The instance goes in the subnet you give it; use a public
  subnet, or add your own NAT/ALB if agents reach it privately.
- **AWS only.** GCP is not implemented — the issue asked for "AWS and/or GCP".
  The shape (instance + firewall + secret manager + instance identity) ports
  cleanly to GCP if you need it.

## Verification

`terraform fmt -check` and `terraform validate` run in CI for both the module
and the example, so a broken reference or a bad type fails the build rather than
the next `apply`.

Nothing here has been `apply`ed against a real AWS account — it is validated,
not battle-tested. Review the plan before you trust it.

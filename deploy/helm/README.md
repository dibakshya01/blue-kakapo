# Deploying blue-kakapo on Kubernetes

A hardened Helm chart (non-root, read-only rootfs, dropped capabilities, no mounted SA token).

## Install

```bash
helm install blue-kakapo deploy/helm/blue-kakapo \
  --namespace blue-kakapo --create-namespace \
  --set database.url="postgresql+psycopg://kakapo@my-postgres:5432/kakapo" \
  --set existingSecret=blue-kakapo-secrets \
  --set config.authEnabled=true \
  --set config.oidcIssuer="https://idp.example" \
  --set config.oidcJwksUrl="https://idp.example/.well-known/jwks.json"
```

## Secrets

Supply credentials via an existing Secret (recommended: **External Secrets Operator** backed by
**OpenBao/Vault**), never in values. Expected keys (all optional): `database-password`,
`anthropic-api-key`, `openai-api-key`, `openbao-token`.

## Supply chain

Release images are **cosign-signed (keyless)** and carry an **SPDX SBOM attestation**. Verify before
deploy:

```bash
cosign verify ghcr.io/dibakshya01/blue-kakapo:<tag> \
  --certificate-identity-regexp 'https://github.com/dibakshya01/blue-kakapo/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type spdxjson ghcr.io/dibakshya01/blue-kakapo:<tag> ...
```

## Air-gapped

Use the [Zarf package](../zarf/zarf.yaml): `zarf package create deploy/zarf` on a connected host, then
`zarf package deploy` inside the air gap. It bundles the signed image, this chart, and pgvector.

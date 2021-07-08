---
layout: "vault"
page_title: "Vault: vault_token resource"
sidebar_current: "docs-vault-resource-token"
description: |-
  Writes token for Vault
---

# vault\_token

Provides a resource to generate a vault token with its options. The token renewing is supported through optional
arguments.

The token used by Terraform will require update access to the `auth/token/lookup-accessor`
path to create tokens and the `auth/token/revoke-accessor` path in Vault to
destroy a token.

```hcl
path "auth/token/lookup-accessor" {
  capabilities = ["update"]
}

path "auth/token/revoke-accessor" {
  capabilities = ["update"]
}
```

## Example Usage

```hcl
resource "vault_token" "example" {
  role_name = "app"

  policies = ["policy1", "policy2"]

  renewable = true
  ttl = "24h"

  renew_min_lease = 43200
  renew_increment = 86400

  metadata = {
    "purpose" = "service-account"
  }

  gpg_key = "keybase:my_username"
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Optional) The token role name

* `policies` - (Optional) List of policies to attach to this token

* `no_parent` - (Optional) Flag to create a token without parent

* `no_default_policy` - (Optional) Flag to not attach the default policy to this token

* `renewable` - (Optional) Flag to allow to renew this token

* `ttl` - (Optional) The TTL period of this token

* `explicit_max_ttl` - (Optional) The explicit max TTL of this token

* `display_name` - (Optional) String containing the token display name

* `num_uses` - (Optional) The number of allowed uses of this token

* `period` - (Optional) The period of this token

* `renew_min_lease` - (Optional) The minimal lease to renew this token

* `renew_increment` - (Optional) The renew increment

* `pgp_key` - (Optional) The PGP key with which the `client_token` will be encrypted.
   The key must be provided using either a base64 encoded non-armored PGP key, or a keybase
   username in the form `keybase:somebody`.
   The token won't be renewed automatically by the provider and `client_token` will be empty.
   **If you do not set this argument, the `client_token` will be written as plain text in the
   Terraform state.**

* `metadata` - (Optional) Metadata to be set on this token

## Attributes Reference

* `lease_duration` - String containing the token lease duration if present in state file

* `lease_started` - String containing the token lease started time if present in state file

* `client_token` - String containing the client token if stored in present file

* `encrypted_client_token` - String containing the client token encrypted with the given `pgp_key` if stored in present file

## Import

Tokens can be imported using its `id` as accessor id, e.g.

```
$ terraform import vault_token.example <accessor_id>
```

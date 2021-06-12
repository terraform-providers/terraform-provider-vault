---
layout: "vault"
page_title: "Vault: vault_approle_auth_backend_role_secret_id resource"
sidebar_current: "docs-vault-resource-approle-auth-backend-role-secret-id"
description: |-
  Manages AppRole auth backend role SecretIDs in Vault.
---

# vault\_approle\_auth\_backend\_role\_secret\_id

Manages an AppRole auth backend SecretID in a Vault server. See the [Vault
documentation](https://www.vaultproject.io/docs/auth/approle) for more
information.

## Example Usage

```hcl
resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_approle_auth_backend_role" "example" {
  backend         = "${vault_auth_backend.approle.path}"
  role_name       = "test-role"
  token_policies  = ["default", "dev", "prod"]
}

resource "vault_approle_auth_backend_role_secret_id" "id" {
  backend   = "${vault_auth_backend.approle.path}"
  role_name = "${vault_approle_auth_backend_role.example.role_name}"

  metadata = <<EOT
{
  "hello": "world"
}
EOT
}
```

## Argument Reference

The following arguments are supported:

* `role_name` - (Required) The name of the role to create the SecretID for.

* `metadata` - (Optional) A JSON-encoded string containing metadata in
  key-value pairs to be set on tokens issued with this SecretID.

* `cidr_list` - (Optional) If set, specifies blocks of IP addresses which can
  perform the login operation using this SecretID.

* `secret_id` - (Optional) The SecretID to be created. If set, uses "Push"
  mode.  Defaults to Vault auto-generating SecretIDs.

* `wrapping_ttl` - (Optional) If set, the SecretID response will be
  [response-wrapped](https://www.vaultproject.io/docs/concepts/response-wrapping)
  and available for the duration specified. Only a single unwrapping of the
  token is allowed.

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `accessor` - The unique ID for this SecretID that can be safely logged.

* `wrapping_accessor` - The unique ID for the response-wrapped SecretID that can
   be safely logged.

* `wrapping_token` - The token used to retrieve a response-wrapped SecretID.

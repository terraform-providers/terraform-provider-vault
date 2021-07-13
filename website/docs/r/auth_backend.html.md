---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-auth-backend"
description: |-
  Writes auth methods for Vault
---

# vault\_auth\_backend


## Example Usage

```hcl
resource "vault_auth_backend" "example" {
  type = "github"

  tune {
    max_lease_ttl      = "90000s"
    listing_visibility = "unauth"
  }
}
```

## Argument Reference

The following arguments are supported:

* `type` - (Required) The name of the auth method type

* `path` - (Optional) The path to mount the auth method — this defaults to the name of the type. Note that leading slashes will be auto-removed if used.

* `description` - (Optional) A description of the auth method

* `local` - (Optional) Specifies if the auth method is local only.

* `tune` - (Optional) Extra configuration block. Structure is documented below.

The `tune` block is used to tune the auth backend:

* `default_lease_ttl` - (Optional) Specifies the default time-to-live.
  If set, this overrides the global default.
  Must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration)

* `max_lease_ttl` - (Optional) Specifies the maximum time-to-live.
  If set, this overrides the global default.
  Must be a valid [duration string](https://golang.org/pkg/time/#ParseDuration)

* `audit_non_hmac_response_keys` - (Optional) Specifies the list of keys that will
  not be HMAC'd by audit devices in the response data object.

* `audit_non_hmac_request_keys` - (Optional) Specifies the list of keys that will
  not be HMAC'd by audit devices in the request data object.

* `listing_visibility` - (Optional) Specifies whether to show this mount in
  the UI-specific listing endpoint. Valid values are "unauth" or "hidden".

* `passthrough_request_headers` - (Optional) List of headers to whitelist and
  pass from the request to the backend.

* `allowed_response_headers` - (Optional) List of headers to whitelist and allowing
  a plugin to include them in the response.

* `token_type` - (Optional) Specifies the type of tokens that should be returned by
  the mount. Valid values are "default-service", "default-batch", "service", "batch".

## Attributes Reference

In addition to the fields above, the following attributes are exported:

* `accessor` - The accessor for this auth method

### Deprecated Arguments

These arguments are deprecated since version 1.8 of the provider in favour of the `tune` block
arguments documented above.

* `default_lease_ttl_seconds` - (Optional; Deprecated, use `tune.default_lease_ttl` if you are using Vault provider version >= 1.8) The default lease duration in seconds.

* `max_lease_ttl_seconds` - (Optional; Deprecated, use `tune.max_lease_ttl` if you are using Vault provider version >= 1.8) The maximum lease duration in seconds.

* `listing_visibility` - (Optional; Deprecated, use `tune.listing_visibility` if you are using Vault provider version >= 1.8) Speficies whether to show this mount in the UI-specific listing endpoint.

## Import

Auth methods can be imported using the `path`, e.g.

```
$ terraform import vault_auth_backend.example github
```

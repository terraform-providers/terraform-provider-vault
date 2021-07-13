---
layout: "vault"
page_title: "Vault: vault_auth_backend resource"
sidebar_current: "docs-vault-resource-okta-auth-backend"
description: |-
  Managing Okta auth backends in Vault
---

# vault\_okta\_auth\_backend

Provides a resource for managing an
[Okta auth backend within Vault](https://www.vaultproject.io/docs/auth/okta.html).

## Example Usage

```hcl
resource "vault_okta_auth_backend" "example" {
    description  = "Demonstration of the Terraform Okta auth backend"
    organization = "example"
    token        = "something that should be kept secret"
    
    group {
        group_name = "foo"
        policies   = ["one", "two"]
    }
    
    user {
        username = "bar"
        groups   = ["foo"]
    }
}
```

## Argument Reference

The following arguments are supported:

* `path` - (Required) Path to mount the Okta auth backend

* `description` - (Optional) The description of the auth backend

* `organization` - (Required) The Okta organization. This will be the first part of the url `https://XXX.okta.com`

* `token` - (Optional) The Okta API token. This is required to query Okta for user group membership.
If this is not supplied only locally configured groups will be enabled.

* `base_url` - (Optional) The Okta url. Examples: oktapreview.com, okta.com

* `bypass_okta_mfa` - (Optional) When true, requests by Okta for a MFA check will be bypassed. This also disallows certain status checks on the account, such as whether the password is expired.

* `ttl` - (Optional) Duration after which authentication will be expired.
[See the documentation for info on valid duration formats](https://golang.org/pkg/time/#ParseDuration).

* `max_ttl` - (Optional) Maximum duration after which authentication will be expired
[See the documentation for info on valid duration formats](https://golang.org/pkg/time/#ParseDuration).

* `group` - (Optional) Associate Okta groups with policies within Vault.
[See below for more details](#okta-group). 

* `user` - (Optional) Associate Okta users with groups or policies within Vault.
[See below for more details](#okta-user). 

* tune - (Optional) Extra configuration block. Structure is documented below.

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

### Okta Group

* `group_name` - (Required) Name of the group within the Okta

* `policies` - (Optional) Vault policies to associate with this group

### Okta User

* `username` - (Required Optional) Name of the user within Okta

* `groups` - (Optional) List of Okta groups to associate with this user

* `policies` - (Optional) List of Vault policies to associate with this user

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `accessor` - The mount accessor related to the auth mount. It is useful for integration with [Identity Secrets Engine](https://www.vaultproject.io/docs/secrets/identity/index.html).

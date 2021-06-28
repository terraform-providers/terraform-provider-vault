---
layout: "vault"
page_title: "Vault: vault_quota_rate_limit resource"
sidebar_current: "docs-vault-quota-rate-limit"
description: |-
  Manage Rate Limit Quota
---

# vault\_quota\_rate\_limit

Manage rate limit quotas which enforce API rate limiting using a token bucket algorithm.
A rate limit quota can be created at the root level or defined on a namespace or mount by
specifying a path when creating the quota.

See [Vault's Documentation](https://www.vaultproject.io/docs/concepts/resource-quotas) for more
information.

## Example Usage

```hcl
resource "vault_quota_rate_limit" "global" {
  name = "global"
  path = ""
  rate = 100
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) Name of the rate limit quota

* `path` - (Optional) Path of the mount or namespace to apply the quota. A blank path configures a
  global rate limit quota. For example `namespace1/` adds a quota to a full namespace,
  `namespace1/auth/userpass` adds a `quota` to `userpass` in `namespace1`.
  Updating this field on an existing quota can have "moving" effects. For example, updating
  `auth/userpass` to `namespace1/auth/userpass` moves this quota from being a global mount quota to
  a namespace specific mount quota. **Note, namespaces are supported in Enterprise only.**

* `rate` - (Required) The maximum number of requests at any given second to be allowed by the quota
  rule. The `rate` must be positive.

* `interval` - (Optional) The duration to enforce rate limiting for (default "1s").

* `block_interval` - (Optional) If set, when a client reaches a rate limit threshold, the client will
  be prohibited from any further requests until after the 'block_interval' has elapsed.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

Rate limit quotas can be imported using their names

```
$ terraform import vault_quota_rate_limit.global global
```

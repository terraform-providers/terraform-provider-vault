---
layout: "vault"
page_title: "Provider: Vault"
sidebar_current: "docs-vault-index"
description: |-
  The Vault provider allows Terraform to read from, write to, and configure HashiCorp Vault
---

# Vault Provider

The Vault provider allows Terraform to read from, write to, and configure
[HashiCorp Vault](https://vaultproject.io/).

~> **Important** Interacting with Vault from Terraform causes any secrets
that you read and write to be persisted in both Terraform's state file
*and* in any generated plan files. For any Terraform module that reads or
writes Vault secrets, these files should be treated as sensitive and
protected accordingly.

This provider serves two pretty-distinct use-cases, which each have their
own security trade-offs and caveats that are covered in the sections that
follow. Consider these carefully before using this provider within your
Terraform configuration.

-> Visit the [Inject secrets into Terraform using the Vault provider](https://learn.hashicorp.com/tutorials/terraform/secrets-vault?utm_source=WEBSITE&utm_medium=WEB_IO&utm_offer=ARTICLE_PAGE&utm_content=DOCS) Learn tutorial to learn how to use
short-lived credentials from Vault's AWS Secrets Engine to authenticate the
AWS provider.

## Best Practices

We recommend that you avoid placing secrets in your Terraform config or state file wherever possible, and if placed there, you take steps to reduce and manage your risk. We have created a practical guide on how to do this with our opensource versions in Best Practices for Using HashiCorp Terraform with HashiCorp Vault:

[![Best Practices for Using HashiCorp Terraform with HashiCorp Vault](https://img.youtube.com/vi/fOybhcbuxJ0/0.jpg)](https://www.youtube.com/watch?v=fOybhcbuxJ0)

This webinar walks you through how to protect secrets when using Terraform with Vault. Additional security measures are available in paid Terraform versions as well.

## Configuring and Populating Vault

Terraform can be used by the Vault administrators to configure Vault and
populate it with secrets. In this case, the state and any plans associated
with the configuration must be stored and communicated with care, since they
will contain in cleartext any values that were written into Vault.

Currently Terraform has no mechanism to redact or protect secrets
that are provided via configuration, so teams choosing to use Terraform
for populating Vault secrets should pay careful attention to the notes
on each resource's documentation page about how any secrets are persisted
to the state and consider carefully whether such usage is compatible with
their security policies.

Except as otherwise noted, the resources that write secrets into Vault are
designed such that they require only the *create* and *update* capabilities
on the relevant resources, so that distinct tokens can be used for reading
vs. writing and thus limit the exposure of a compromised token.

## Using Vault credentials in Terraform configuration

Most Terraform providers require credentials to interact with a third-party
service that they wrap. This provider allows such credentials to be obtained
from Vault, which means that operators or systems running Terraform need
only access to a suitably-privileged Vault token in order to temporarily
lease the credentials for other providers.

Currently Terraform has no mechanism to redact or protect secrets that
are returned via data sources, so secrets read via this provider will be
persisted into the Terraform state, into any plan files, and in some cases
in the console output produced while planning and applying. These artifacts
must therefore all be protected accordingly.

To reduce the exposure of such secrets, the provider requests a Vault token
with a relatively-short TTL (20 minutes, by default) which in turn means
that where possible Vault will revoke any issued credentials after that
time, but in particular it is unable to retract any static secrets such as
those stored in Vault's "generic" secret backend.

The requested token TTL can be controlled by the `max_lease_ttl_seconds`
provider argument described below. It is important to consider that Terraform
reads from data sources during the `plan` phase and writes the result into
the plan. Thus a subsequent `apply` will likely fail if it is run after the
intermediate token has expired, due to the revocation of the secrets that
are stored in the plan.

Except as otherwise noted, the resources that read secrets from Vault
are designed such that they require only the *read* capability on the relevant
resources.

## Provider Arguments

The provider configuration block accepts the following arguments.
In most cases it is recommended to set them via the indicated environment
variables in order to keep credential information out of the configuration.

* `address` - (Required) Origin URL of the Vault server. This is a URL
  with a scheme, a hostname and a port but with no path. May be set
  via the `VAULT_ADDR` environment variable.

* `add_address_to_env` - (Optional) If `true` the environment variable
  `VAULT_ADDR` in the Terraform process environment will be set to the
  value of the `address` argument from this provider. By default, this is false.

* `token` - (Required) Vault token that will be used by Terraform to
  authenticate. May be set via the `VAULT_TOKEN` environment variable.
  If none is otherwise supplied, Terraform will attempt to read it from
  `~/.vault-token` (where the vault command stores its current token).
  Terraform will issue itself a new token that is a child of the one given,
  with a short TTL to limit the exposure of any requested secrets. Note that
  the given token must have the update capability on the auth/token/create
  path in Vault in order to create child tokens.

* `token_name` - (Optional) Token name, that will be used by Terraform when
  creating the child token (`display_name`). This is useful to provide a reference of the
  Terraform run traceable in vault audit log, e.g. commit hash or id of the CI/CD
  execution job. May be set via the `VAULT_TOKEN_NAME` environment variable.
  Default value will be `terraform` if not set or empty.

* `ca_cert_file` - (Optional) Path to a file on local disk that will be
  used to validate the certificate presented by the Vault server.
  May be set via the `VAULT_CACERT` environment variable.

* `ca_cert_dir` - (Optional) Path to a directory on local disk that
  contains one or more certificate files that will be used to validate
  the certificate presented by the Vault server. May be set via the
  `VAULT_CAPATH` environment variable.

* `auth_login` - (Optional) A configuration block, described below, that
  attempts to authenticate using the `auth/<method>/login` path to
  aquire a token which Terraform will use. Terraform still issues itself
  a limited child token using auth/token/create in order to enforce a short
  TTL and limit exposure.

* `client_auth` - (Optional) A configuration block, described below, that
  provides credentials used by Terraform to authenticate with the Vault
  server. At present there is little reason to set this, because Terraform
  does not support the TLS certificate authentication mechanism.

* `skip_tls_verify` - (Optional) Set this to `true` to disable verification
  of the Vault server's TLS certificate. This is strongly discouraged except
  in prototype or development environments, since it exposes the possibility
  that Terraform can be tricked into writing secrets to a server controlled
  by an intruder. May be set via the `VAULT_SKIP_VERIFY` environment variable.

* `create_intermediate_child_token` - (Optional) Set this to `false` to disable
  creation and use of an intermediate ephemeral Vault token for Terraform to
  use. This is strongly discouraged in most cases and environments because it
  can result in the provided Vault token being exposed by Terraform's output.
  Only change this setting when the provided token cannot be permitted to
  create child tokens and there is no risk of exposure from the output of
  Terraform. May be set via the `TERRAFORM_VAULT_CREATE_CHILD_TOKEN`
  environment variable. **Note**: Setting to `false` will cause `token_name`
  and `max_lease_ttl_seconds` to be ignored.

  See the section above on *Using Vault credentials in Terraform configuration*
  for more details on why it is not recommended to disable this setting.

* `max_lease_ttl_seconds` - (Optional) Used as the duration for the
  intermediate Vault token Terraform issues itself, which in turn limits
  the duration of secret leases issued by Vault. Defaults to 20 minutes
  and may be set via the `TERRAFORM_VAULT_MAX_TTL` environment variable.
  See the section above on *Using Vault credentials in Terraform configuration*
  for the implications of this setting.

* `max_retries` - (Optional) Used as the maximum number of retries when a 5xx
  error code is encountered. Defaults to 2 retries and may be set via the
  `VAULT_MAX_RETRIES` environment variable.

* `namespace` - (Optional) Set the namespace to use. May be set via the
  `VAULT_NAMESPACE` environment variable. *Available only for Vault Enterprise*.

* `headers` - (Optional) A configuration block, described below, that provides headers
to be sent along with all requests to the Vault server.  This block can be specified
multiple times.

The `auth_login` configuration block accepts the following arguments:

* `path` - (Required) The login path of the auth backend. For example, login with
  approle by setting this path to `auth/approle/login`. Additionally, some mounts use parameters
  in the URL, like with `userpass`: `auth/userpass/login/:username`.

* `namespace` - (Optional) The path to the namespace that has the mounted auth method.
  This defaults to the root namespace. Cannot contain any leading or trailing slashes.
  *Available only for Vault Enterprise*

* `method` - (Optional) When configured, will enable auth method specific operations.
  For example, when set to `aws`, the provider will automatically sign login requests
  for AWS authentication. Valid values include: `aws`.

* `parameters` - (Optional) A map of key-value parameters to send when authenticating
  against the auth backend. Refer to [Vault API documentation](https://www.vaultproject.io/api-docs/auth) for a particular auth method
  to see what can go here.

The `client_auth` configuration block accepts the following arguments:

* `cert_file` - (Required) Path to a file on local disk that contains the
  PEM-encoded certificate to present to the server.

* `key_file` - (Required) Path to a file on local disk that contains the
  PEM-encoded private key for which the authentication certificate was issued.

The `headers` configuration block accepts the following arguments:

* `name` - (Required) The name of the header.

* `value` - (Required) The value of the header.

## Example Usage

```hcl
provider "vault" {
  # It is strongly recommended to configure this provider through the
  # environment variables described above, so that each user can have
  # separate credentials set in the environment.
  #
  # This will default to using $VAULT_ADDR
  # But can be set explicitly
  # address = "https://vault.example.net:8200"
}

resource "vault_generic_secret" "example" {
  path = "secret/foo"

  data_json = <<EOT
{
  "foo":   "bar",
  "pizza": "cheese"
}
EOT
}
```

### Example `auth_login` Usage
With the `userpass` backend:

```hcl
variable login_username {}
variable login_password {}

provider "vault" {
  auth_login {
    path = "auth/userpass/login/${var.login_username}"

    parameters = {
      password = var.login_password
    }
  }
}
```

Or, using `approle`:

```hcl
variable login_approle_role_id {}
variable login_approle_secret_id {}

provider "vault" {
  auth_login {
    path = "auth/approle/login"

    parameters = {
      role_id   = var.login_approle_role_id
      secret_id = var.login_approle_secret_id
    }
  }
}
```

### Example `auth_login` With AWS Signing

Sign AWS metadata for instance profile login requests:

```hcl
provider "vault" {
  address = "http://127.0.0.1:8200"
  auth_login {
    path = "auth/aws/login"
    method = "aws"
    parameters = {
      role = "dev-role-iam"
    }
  }
}
```

## Namespace support

The Vault provider supports managing [Namespaces][namespaces] (a feature of
Vault Enterprise), as well as creating resources in those namespaces by
utilizing [Provider Aliasing][aliasing]. The `namespace` option in the [provider
block][provider-block] enables the management of  resources in the specified
namespace.

### Using Provider Aliases

The below configuration is a simple example of using the provider block's
`namespace` attribute to configure an aliased provider and create a resource
within that namespace.

```hcl
# main provider block with no namespace
provider vault {}

# create the "everyone" namespace in the default root namespace
resource "vault_namespace" "everyone" {
  path = "everyone"
}

# configure an aliased provider, scope to the new namespace.
provider vault {
  alias     = "everyone"
  namespace = vault_namespace.everyone.path
}

# create a policy in the "everyone" namespace
resource "vault_policy" "example" {
  provider = vault.everyone

  depends_on = [vault_namespace.everyone]
  name       = "vault_everyone_policy"
  policy     = data.vault_policy_document.list_secrets.hcl
}

data "vault_policy_document" "list_secrets" {
  rule {
    path         = "secret/*"
    capabilities = ["list"]
    description  = "allow List on secrets under everyone/"
  }
}
```

Using this alias configuration, the policy `list_secrets` is created under the
`everyone` namespace, but not under the "root" namespace:

```
$ vault policy list -namespace=everyone
default
vault_everyone_policy

$ vault policy list
default
root
```

### Nested Namespaces

A more complex example of nested namespaces is show below. Each provider blocks
uses interpolation of the `ID` of namespace it belongs in to ensure the namespace
exists before that provider gets configured:


```hcl
# main provider block with no namespace
provider vault {}

resource "vault_namespace" "everyone" {
  path = "everyone"
}

provider vault {
  alias     = "everyone"
  namespace = trimsuffix(vault_namespace.everyone.id, "/")
}

data "vault_policy_document" "public_secrets" {
  rule {
    path         = "secret/*"
    capabilities = ["list"]
    description  = "allow List on secrets under everyone/ namespace"
  }
}

resource "vault_policy" "everyone" {
  provider = vault.everyone
  name     = "vault_everyone_policy"
  policy   = data.vault_policy_document.vault_team_secrets.hcl
}

resource "vault_namespace" "engineering" {
  provider = vault.everyone
  path     = "engineering"
}

provider vault {
  alias = "engineering"
  namespace = trimsuffix(vault_namespace.engineering.id, "/")
}

resource "vault_namespace" "vault-team" {
  provider = vault.engineering
  path     = "vault-team"
}

data "vault_policy_document" "vault_team_secrets" {
  rule {
    path         = "secret/*"
    capabilities = ["create", "read", "update", "delete", "list"]
    description  = "allow all on secrets under everyone/engineering/vault-team/"
  }
}

provider vault {
  alias = "vault-team"
  namespace = trimsuffix(vault_namespace.vault-team.id, "/")
}

resource "vault_policy" "vault_team" {
  provider = vault.vault-team
  name     = "vault_team_policy"
  policy   = data.vault_policy_document.vault_team_secrets.hcl
}
```

Using this configuration, the namespace and policy structure looks like so:

```
<root>/
  default
  root
  /everyone/
   default
   vault_everyone_policy
    /engineering/
      default
      /vault-team/
      default
      vault_team_policy
```

Verify the structure with `vault` directly:

```
$ vault namespace list
Keys
----
everyone/

$ vault namespace list -namespace=everyone
Keys
----
engineering/

$ vault namespace list -namespace=everyone/engineering
Keys
----
vault-team/

$ vault namespace list -namespace=everyone/engineering/vault-team
No namespaces found

$ vault namespace list -namespace=everyone/engineering/vault-team

$ vault policy list -namespace=everyone/engineering/vault-team
default
vault_team_policy
```


[namespaces]: https://www.vaultproject.io/docs/enterprise/namespaces#vault-enterprise-namespaces
[aliasing]: https://www.terraform.io/docs/configuration/providers.html#alias-multiple-provider-configurations
[provider-block]: /docs#provider-arguments

---
layout: "vault"
page_title: "Vault: vault_gcp_secret_static_account resource"
sidebar_current: "docs-vault-resource-gcp-secret-statoc-account"
description: |-
  Creates a Static Account for the GCP Secret Backend for Vault.
---

# vault\_gcp\_secret\_static\_account

Creates a Static Account in the [GCP Secrets Engine](https://www.vaultproject.io/docs/secrets/gcp/index.html) for Vault.

Each [static account](https://www.vaultproject.io/docs/secrets/gcp/index.html#static-accounts) is tied to a separately managed
Service Account, and can have one or more [bindings](https://www.vaultproject.io/docs/secrets/gcp/index.html#bindings) associated with it.

## Example Usage

```hcl
resource "google_service_account" "this" {
  account_id = "my-awesome-account"
}

resource "vault_gcp_secret_backend" "gcp" {
  path        = "gcp"
  credentials = "${file("credentials.json")}"
}

resource "vault_gcp_secret_static_account" "static_account" {
  backend        = vault_gcp_secret_backend.gcp.path
  static_account = "project_viewer"
  secret_type    = "access_token"
  token_scopes   = ["https://www.googleapis.com/auth/cloud-platform"]

  service_account_email = google_service_account.this.email

  # Optional
  binding {
    resource = "//cloudresourcemanager.googleapis.com/projects/${google_service_account.this.project}"

    roles = [
      "roles/viewer",
    ]
  }
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required, Forces new resource) Path where the GCP Secrets Engine is mounted

* `static_account` - (Required, Forces new resource) Name of the Static Account to create

* `service_account_email` - (Required, Forces new resource) Email of the GCP service account to manage.

* `secret_type` - (Optional, Forces new resource) Type of secret generated for this role set. Accepted values: `access_token`, `service_account_key`. Defaults to `access_token`.

* `token_scopes` - (Optional, Required for `secret_type = "access_token"`) List of OAuth scopes to assign to `access_token` secrets generated under this role set (`access_token` role sets only).

* `binding` - (Optional) Bindings to create for this static account. This can be specified multiple times for multiple bindings. Structure is documented below.

The `binding` block supports:

* `resource` - (Required) Resource or resource path for which IAM policy information will be bound. The resource path may be specified in a few different [formats](https://www.vaultproject.io/docs/secrets/gcp/index.html#bindings).

* `roles` - (Required) List of [GCP IAM roles](https://cloud.google.com/iam/docs/understanding-roles) for the resource.

## Attributes Reference

In addition to the fields above, the following attributes are also exposed:

* `service_account_project` - Project the service account belongs to.

## Import

A static account can be imported using its Vault Path. For example, referencing the example above,

```
$ terraform import vault_gcp_secret_static_account.static_account gcp/static-account/project_viewer
```

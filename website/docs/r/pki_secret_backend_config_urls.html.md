---
layout: "vault"
page_title: "Vault: vault_pki_secret_backend_config_urls resource"
sidebar_current: "docs-vault-resource-pki-secret-backend-config-urls"
description: |-
  Sets the config URL's on an PKI Secret Backend for Vault.
---

# vault\_pki\_secret\_backend\_config\_urls

Allows setting the issuing certificate endpoints, CRL distribution points, and OCSP server endpoints that will be encoded into issued certificates.

## Example Usage

```hcl
resource "vault_pki_secret_backend" "pki" {
  path                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_config_urls" "config_urls" {
  backend              = vault_pki_secret_backend.pki.path
  issuing_certificates = ["http://127.0.0.1:8200/v1/pki/ca"]
}
```

## Argument Reference

The following arguments are supported:

* `backend` - (Required) The path the PKI secret backend is mounted at, with no leading or trailing `/`s.

* `issuing_certificates` - (Optional) Specifies the URL values for the Issuing Certificate field.

* `crl_distribution_points` - (Optional) Specifies the URL values for the CRL Distribution Points field.

* `ocsp_servers` - (Optional) Specifies the URL values for the OCSP Servers field.

## Attributes Reference

No additional attributes are exported by this resource.

## Import

PKI secret backend config urls can be imported using the pki secret backend name itself, e.g.

```
$ terraform import vault_pki_secret_backend_config_urls.pki pki
```

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	"github.com/hashicorp/vault/api"
)

func certAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"name": {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		"certificate": {
			Type:     schema.TypeString,
			Required: true,
			ForceNew: true,
		},
		"allowed_names": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"allowed_common_names": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"allowed_dns_sans": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"allowed_email_sans": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"allowed_uri_sans": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"allowed_organizational_units": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			Computed:      true,
			ConflictsWith: []string{"allowed_organization_units"},
		},
		"required_extensions": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			Computed: true,
		},
		"display_name": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"backend": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
			Default:  "cert",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},

		// Deprecated
		"allowed_organization_units": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			Computed:      true,
			ConflictsWith: []string{"allowed_organizational_units"},
			Deprecated:    "use `allowed_organizational_units` instead",
		},
		"bound_cidrs": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			Computed:      true,
			Deprecated:    "use `token_bound_cidrs` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_bound_cidrs"},
		},
		"ttl": {
			Type:          schema.TypeString,
			Optional:      true,
			Computed:      true,
			Deprecated:    "use `token_ttl` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_ttl"},
		},
		"max_ttl": {
			Type:          schema.TypeString,
			Optional:      true,
			Computed:      true,
			Deprecated:    "use `token_max_ttl` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_max_ttl"},
		},
		"period": {
			Type:          schema.TypeString,
			Optional:      true,
			Computed:      true,
			Deprecated:    "use `token_period` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_period"},
		},
		"policies": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			Computed:      true,
			Deprecated:    "use `token_policies` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_policies"},
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{
		TokenBoundCidrsConflict: []string{"bound_cidrs"},
		TokenMaxTTLConflict:     []string{"max_ttl"},
		TokenPoliciesConflict:   []string{"policies"},
		TokenPeriodConflict:     []string{"period"},
		TokenTTLConflict:        []string{"ttl"},
	})

	return &schema.Resource{
		SchemaVersion: 1,

		Create: certAuthResourceWrite,
		Update: certAuthResourceUpdate,
		Read:   certAuthResourceRead,
		Delete: certAuthResourceDelete,

		Schema: fields,
	}
}

func certCertResourcePath(backend, name string) string {
	return "auth/" + strings.Trim(backend, "/") + "/certs/" + strings.Trim(name, "/")
}

func certAuthResourceWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	path := certCertResourcePath(backend, name)

	data := map[string]interface{}{}
	updateTokenFields(d, data, true)

	data["certificate"] = d.Get("certificate")

	if v, ok := d.GetOk("allowed_names"); ok {
		data["allowed_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_common_names"); ok {
		data["allowed_common_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_dns_sans"); ok {
		data["allowed_dns_sans"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_uri_sans"); ok {
		data["allowed_uri_sans"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_organization_units"); ok {
		data["allowed_organization_units"] = v.(*schema.Set).List()
	} else if v, ok := d.GetOk("allowed_organizational_units"); ok {
		data["allowed_organizational_units"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("required_extensions"); ok {
		data["required_extensions"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("display_name"); ok {
		data["display_name"] = v.(string)
	}

	// Deprecated fields
	if v, ok := d.GetOk("bound_cidrs"); ok {
		data["bound_cidrs"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(string)
	}

	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(string)
	}

	if v, ok := d.GetOk("period"); ok {
		data["period"] = v.(string)
	}

	if v, ok := d.GetOk("policies"); ok {
		data["policies"] = v.(*schema.Set).List()
	}

	log.Printf("[DEBUG] Writing %q to cert auth backend", path)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error writing %q to cert auth backendq: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote %q to cert auth backend", path)

	return certAuthResourceRead(d, meta)
}

func certAuthResourceUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	data := map[string]interface{}{}
	updateTokenFields(d, data, false)

	data["certificate"] = d.Get("certificate")

	if v, ok := d.GetOk("allowed_names"); ok {
		data["allowed_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_common_names"); ok {
		data["allowed_common_names"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_dns_sans"); ok {
		data["allowed_dns_sans"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_uri_sans"); ok {
		data["allowed_uri_sans"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("allowed_organization_units"); ok {
		data["allowed_organization_units"] = v.(*schema.Set).List()
	} else if v, ok := d.GetOk("allowed_organizational_units"); ok {
		data["allowed_organizational_units"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("required_extensions"); ok {
		data["required_extensions"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(string)
	}

	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(string)
	}

	if v, ok := d.GetOk("period"); ok {
		data["period"] = v.(string)
	}

	if v, ok := d.GetOk("policies"); ok {
		data["policies"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("display_name"); ok {
		data["display_name"] = v.(string)
	}

	if v, ok := d.GetOk("bound_cidrs"); ok {
		data["bound_cidrs"] = v.(*schema.Set).List()
	}

	log.Printf("[DEBUG] Updating %q in cert auth backend", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("Error updating %q in cert auth backend: %s", path, err)
	}
	log.Printf("[DEBUG] Updated %q in cert auth backend", path)

	return certAuthResourceRead(d, meta)
}

func certAuthResourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading cert %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("Error reading cert %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read cert %q", path)

	if resp == nil {
		log.Printf("[WARN] cert %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	readTokenFields(d, resp)

	// Check if the user is using the deprecated `policies`
	if _, deprecated := d.GetOk("policies"); deprecated {
		// Then we see if `token_policies` was set and unset it
		// Vault will still return `policies`
		if _, ok := d.GetOk("token_policies"); ok {
			d.Set("token_policies", nil)
		}

		if v, ok := resp.Data["policies"]; ok {
			d.Set("policies", v)
		}
	}

	// Check if the user is using the deprecated `period`
	if _, deprecated := d.GetOk("period"); deprecated {
		// Then we see if `token_period` was set and unset it
		// Vault will still return `period`
		if _, ok := d.GetOk("token_period"); ok {
			d.Set("token_period", nil)
		}

		if v, ok := resp.Data["period"]; ok {
			d.Set("period", v)
		}
	}

	// Check if the user is using the deprecated `ttl`
	if _, deprecated := d.GetOk("ttl"); deprecated {
		// Then we see if `token_ttl` was set and unset it
		// Vault will still return `ttl`
		if _, ok := d.GetOk("token_ttl"); ok {
			d.Set("token_ttl", nil)
		}

		if v, ok := resp.Data["ttl"]; ok {
			d.Set("ttl", v)
		}

	}

	// Check if the user is using the deprecated `max_ttl`
	if _, deprecated := d.GetOk("max_ttl"); deprecated {
		// Then we see if `token_max_ttl` was set and unset it
		// Vault will still return `max_ttl`
		if _, ok := d.GetOk("token_max_ttl"); ok {
			d.Set("token_max_ttl", nil)
		}

		if v, ok := resp.Data["max_ttl"]; ok {
			d.Set("max_ttl", v)
		}
	}

	// Check if the user is using the deprecated `bound_cidrs`
	if _, deprecated := d.GetOk("bound_cidrs"); deprecated {
		// Then we see if `token_bound_cidrs` was set and unset it
		// Vault will still return `bound_cidrs`
		if _, ok := d.GetOk("token_bound_cidrs"); ok {
			d.Set("token_bound_cidrs", nil)
		}

		if v, ok := resp.Data["bound_cidrs"]; ok {
			d.Set("bound_cidrs", v)
		}
	}

	// Check if the user is using the deprecated `organization_units`
	if _, deprecated := d.GetOk("organization_units"); deprecated {
		// Then we see if `organizational_units` was set and unset it
		// Vault will still return `organization_units`
		if _, ok := d.GetOk("organizational_units"); ok {
			d.Set("organization_units", nil)
		}

		if v, ok := resp.Data["organization_units"]; ok {
			d.Set("organization_units", v)
		}
	}
	d.Set("certificate", resp.Data["certificate"])
	d.Set("display_name", resp.Data["display_name"])

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_names"] != nil {
		d.Set("allowed_names",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_names"].([]interface{})))
	} else {
		d.Set("allowed_names",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_dns_sans"] != nil {
		d.Set("allowed_dns_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_dns_sans"].([]interface{})))
	} else {
		d.Set("allowed_dns_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_email_sans"] != nil {
		d.Set("allowed_email_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_email_sans"].([]interface{})))
	} else {
		d.Set("allowed_email_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_uri_sans"] != nil {
		d.Set("allowed_uri_sans",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_uri_sans"].([]interface{})))
	} else {
		d.Set("allowed_uri_sans",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_organization_units"] != nil {
		d.Set("allowed_organization_units",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_organization_units"].([]interface{})))
	} else {
		d.Set("allowed_organization_units",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["allowed_organizational_units"] != nil {
		d.Set("allowed_organizational_units",
			schema.NewSet(
				schema.HashString, resp.Data["allowed_organizational_units"].([]interface{})))
	} else {
		d.Set("allowed_organizational_units",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	// Vault sometimes returns these as null instead of an empty list.
	if resp.Data["required_extensions"] != nil {
		d.Set("required_extensions",
			schema.NewSet(
				schema.HashString, resp.Data["required_extensions"].([]interface{})))
	} else {
		d.Set("required_extensions",
			schema.NewSet(
				schema.HashString, []interface{}{}))
	}

	return nil
}

func certAuthResourceDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting cert %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting cert %q", path)
	}
	log.Printf("[DEBUG] Deleted cert %q", path)

	return nil
}

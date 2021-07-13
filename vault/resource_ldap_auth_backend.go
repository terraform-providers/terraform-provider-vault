package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	"github.com/hashicorp/vault/api"
)

const ldapAuthType string = "ldap"

func ldapAuthBackendResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"url": {
			Type:     schema.TypeString,
			Required: true,
		},
		"starttls": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"tls_min_version": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"tls_max_version": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"insecure_tls": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"certificate": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"binddn": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"bindpass": {
			Type:      schema.TypeString,
			Optional:  true,
			Computed:  true,
			Sensitive: true,
		},
		"case_sensitive_names": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"userdn": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"userattr": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
			StateFunc: func(v interface{}) string {
				return strings.ToLower(v.(string))
			},
		},
		"discoverdn": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"deny_null_bind": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},
		"upndomain": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"groupfilter": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"groupdn": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"groupattr": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"use_token_groups": {
			Type:     schema.TypeBool,
			Optional: true,
			Computed: true,
		},

		"description": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},

		"path": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
			Default:  "ldap",
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},

		"accessor": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "The accessor of the LDAP auth backend",
		},
		"client_tls_cert": {
			Type:     schema.TypeString,
			Optional: true,
			Computed: true,
		},
		"client_tls_key": {
			Type:      schema.TypeString,
			Optional:  true,
			Computed:  true,
			Sensitive: true,
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{})

	return &schema.Resource{
		SchemaVersion: 1,

		Create: ldapAuthBackendWrite,
		Update: ldapAuthBackendUpdate,
		Read:   ldapAuthBackendRead,
		Delete: ldapAuthBackendDelete,
		Exists: ldapAuthBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

func ldapAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}

func ldapAuthBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	authType := ldapAuthType
	path := d.Get("path").(string)
	desc := d.Get("description").(string)

	log.Printf("[DEBUG] Enabling LDAP auth backend %q", path)
	err := client.Sys().EnableAuth(path, authType, desc)
	if err != nil {
		return fmt.Errorf("error enabling ldap auth backend %q: %s", path, err)
	}
	log.Printf("[DEBUG] Enabled LDAP auth backend %q", path)

	d.SetId(path)

	return ldapAuthBackendUpdate(d, meta)
}

func ldapAuthBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := ldapAuthBackendConfigPath(d.Id())
	data := map[string]interface{}{}

	if v, ok := d.GetOk("url"); ok {
		data["url"] = v.(string)
	}

	if v, ok := d.GetOkExists("starttls"); ok {
		data["starttls"] = v.(bool)
	}

	if v, ok := d.GetOk("tls_min_version"); ok {
		data["tls_min_version"] = v.(string)
	}

	if v, ok := d.GetOk("tls_max_version"); ok {
		data["tls_max_version"] = v.(string)
	}

	if v, ok := d.GetOkExists("insecure_tls"); ok {
		data["insecure_tls"] = v.(bool)
	}

	if v, ok := d.GetOk("certificate"); ok {
		data["certificate"] = v.(string)
	}

	if v, ok := d.GetOk("binddn"); ok {
		data["binddn"] = v.(string)
	}

	if v, ok := d.GetOk("bindpass"); ok {
		data["bindpass"] = v.(string)
	}

	if v, ok := d.GetOk("case_sensitive_names"); ok {
		data["case_sensitive_names"] = v.(bool)
	}
	
	if v, ok := d.GetOk("userdn"); ok {
		data["userdn"] = v.(string)
	}

	if v, ok := d.GetOk("userattr"); ok {
		data["userattr"] = v.(string)
	}

	if v, ok := d.GetOkExists("discoverdn"); ok {
		data["discoverdn"] = v.(bool)
	}

	if v, ok := d.GetOkExists("deny_null_bind"); ok {
		data["deny_null_bind"] = v.(bool)
	}

	if v, ok := d.GetOk("upndomain"); ok {
		data["upndomain"] = v.(string)
	}

	if v, ok := d.GetOk("groupfilter"); ok {
		data["groupfilter"] = v.(string)
	}

	if v, ok := d.GetOk("groupdn"); ok {
		data["groupdn"] = v.(string)
	}

	if v, ok := d.GetOk("groupattr"); ok {
		data["groupattr"] = v.(string)
	}

	if v, ok := d.GetOkExists("use_token_groups"); ok {
		data["use_token_groups"] = v.(bool)
	}

	if v, ok := d.GetOk("client_tls_cert"); ok {
		data["client_tls_cert"] = v.(string)
	}

	if v, ok := d.GetOk("client_tls_key"); ok {
		data["client_tls_key"] = v.(string)
	}

	updateTokenFields(d, data, false)

	log.Printf("[DEBUG] Writing LDAP config %q", path)
	_, err := client.Logical().Write(path, data)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("error writing ldap config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote LDAP config %q", path)

	return ldapAuthBackendRead(d, meta)
}

func ldapAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	auths, err := client.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	d.Set("path", path)

	authMount := auths[strings.Trim(path, "/")+"/"]
	if authMount == nil {
		return fmt.Errorf("auth mount %s not present", path)
	}

	d.Set("description", authMount.Description)
	d.Set("accessor", authMount.Accessor)

	path = ldapAuthBackendConfigPath(path)

	log.Printf("[DEBUG] Reading LDAP auth backend config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading ldap auth backend config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read LDAP auth backend config %q", path)

	if resp == nil {
		log.Printf("[WARN] LDAP auth backend config %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if err := readTokenFields(d, resp); err != nil {
		return err
	}

	d.Set("url", resp.Data["url"])
	d.Set("starttls", resp.Data["starttls"])
	d.Set("tls_min_version", resp.Data["tls_min_version"])
	d.Set("tls_max_version", resp.Data["tls_max_version"])
	d.Set("insecure_tls", resp.Data["insecure_tls"])
	d.Set("certificate", resp.Data["certificate"])
	d.Set("binddn", resp.Data["binddn"])
	d.Set("case_sensitive_names", resp.Data["case_sensitive_names"])
	d.Set("userdn", resp.Data["userdn"])
	d.Set("userattr", resp.Data["userattr"])
	d.Set("discoverdn", resp.Data["discoverdn"])
	d.Set("deny_null_bind", resp.Data["deny_null_bind"])
	d.Set("upndomain", resp.Data["upndomain"])
	d.Set("groupfilter", resp.Data["groupfilter"])
	d.Set("groupdn", resp.Data["groupdn"])
	d.Set("groupattr", resp.Data["groupattr"])
	d.Set("use_token_groups", resp.Data["use_token_groups"])

	// `bindpass`, `client_tls_cert` and `client_tls_key` cannot be read out from the API
	// So... if they drift, they drift.

	return nil
}

func ldapAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting LDAP auth backend %q", path)
	err := client.Sys().DisableAuth(path)
	if err != nil {
		return fmt.Errorf("error deleting ldap auth backend %q: %q", path, err)
	}
	log.Printf("[DEBUG] Deleted LDAP auth backend %q", path)

	return nil
}

func ldapAuthBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	path := ldapAuthBackendConfigPath(d.Id())

	log.Printf("[DEBUG] Checking if LDAP auth backend %q exists", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking for existence of ldap config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if LDAP auth backend %q exists", path)

	return resp != nil, nil
}

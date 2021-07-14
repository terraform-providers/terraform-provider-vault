package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	gcpSecretRolesetBackendFromPathRegex = regexp.MustCompile("^(.+)/roleset/.+$")
	gcpSecretRolesetNameFromPathRegex    = regexp.MustCompile("^.+/roleset/(.+)$")
)

func gcpSecretRolesetResource() *schema.Resource {
	return &schema.Resource{
		Create: gcpSecretRolesetCreate,
		Read:   gcpSecretRolesetRead,
		Update: gcpSecretRolesetUpdate,
		Delete: gcpSecretRolesetDelete,
		Exists: gcpSecretRolesetExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path where the GCP secrets engine is mounted.",
				ForceNew:    true,
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"roleset": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the RoleSet to create",
				ForceNew:    true,
			},
			"secret_type": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "Type of secret generated for this role set. Defaults to `access_token`. Accepted values: `access_token`, `service_account_key`",
			},
			"project": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the GCP project that this roleset's service account will belong to.",
			},
			"token_scopes": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional:    true,
				Description: "List of OAuth scopes to assign to `access_token` secrets generated under this role set (`access_token` role sets only) ",
			},
			"binding": {
				Type:     schema.TypeSet,
				Required: true,
				Set:      gcpSecretBindingHash,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"resource": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Resource name",
						},
						"roles": {
							Type:        schema.TypeSet,
							Required:    true,
							Description: "List of roles to apply to the resource",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"service_account_email": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Email of the service account created by Vault for this Roleset",
			},
		},

		CustomizeDiff: customdiff.ComputedIf("service_account_email", func(d *schema.ResourceDiff, meta interface{}) bool {
			log.Printf("[DEBUG] Checking if GCP Secrets backend roleset has changes in `token_scopes` or `binding`")
			// Due to https://github.com/hashicorp/terraform/issues/17411
			// we cannot use d.HasChange("binding") directly
			oldBinding, newBinding := d.GetChange("binding")
			oldHcl := gcpSecretRenderBindingsFromData(oldBinding)
			newHcl := gcpSecretRenderBindingsFromData(newBinding)

			return d.HasChange("token_scopes") || oldHcl != newHcl
		}),
	}
}

func gcpSecretRolesetCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	roleset := d.Get("roleset").(string)

	path := gcpSecretRolesetPath(backend, roleset)

	log.Printf("[DEBUG] Writing GCP Secrets backend roleset %q", path)

	data := map[string]interface{}{}
	gcpSecretRolesetUpdateFields(d, data)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error writing GCP Secrets backend roleset %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote GCP Secrets backend roleset %q", path)

	return gcpSecretRolesetRead(d, meta)
}

func gcpSecretRolesetRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	backend, err := gcpSecretRolesetBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for GCP secrets backend roleset: %s", path, err)
	}

	roleset, err := gcpSecretRoleSetdRolesetNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for GCP Secrets backend roleset: %s", path, err)
	}

	log.Printf("[DEBUG] Reading GCP Secrets backend roleset %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading GCP Secrets backend roleset %q: %s", path, err)
	}

	log.Printf("[DEBUG] Read GCP Secrets backend roleset %q", path)
	if resp == nil {
		log.Printf("[WARN] GCP Secrets backend roleset %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set("backend", backend)
	d.Set("roleset", roleset)

	for _, k := range []string{"secret_type", "token_scopes", "service_account_email"} {
		v, ok := resp.Data[k]
		if ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for GCP Secrets backend roleset %q: %q", k, path, err)
			}
		}
	}

	// In https://github.com/hashicorp/vault-plugin-secrets-gcp/pull/28, this field is changed to
	// `project`. We handle cases where it used to be `service_account_project` for backward
	// compatibility.
	project, ok := resp.Data["project"]
	if !ok {
		project, ok = resp.Data["service_account_project"]
		if !ok {
			return fmt.Errorf("error reading %s for GCP Secrets backend roleset %q", "project", path)
		}
	}
	if err := d.Set("project", project); err != nil {
		return fmt.Errorf("error reading %s for GCP Secrets backend roleset %q", "project", path)
	}

	if err := d.Set("binding", gcpSecretFlattenBinding(resp.Data["bindings"])); err != nil {
		return fmt.Errorf("error reading %s for GCP Secrets backend roleset %q", "binding", path)
	}

	return nil
}

func gcpSecretRolesetUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	data := map[string]interface{}{}
	gcpSecretRolesetUpdateFields(d, data)

	log.Printf("[DEBUG] Updating GCP Secrets backend roleset %q", path)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("Error updating GCP Secrets backend roleset %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated GCP Secrets backend roleset %q", path)

	return gcpSecretRolesetRead(d, meta)
}

func gcpSecretRolesetDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting GCP secrets backend roleset %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting GCP secrets backend roleset %q", path)
	}
	log.Printf("[DEBUG] Deleted GCP secrets backend roleset %q", path)

	return nil
}

func gcpSecretRolesetUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	if v, ok := d.GetOk("secret_type"); ok {
		data["secret_type"] = v.(string)
	}

	if v, ok := d.GetOk("project"); ok {
		data["project"] = v.(string)
	}

	if v, ok := d.GetOk("token_scopes"); ok && d.Get("secret_type").(string) == "access_token" {
		data["token_scopes"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("binding"); ok {
		bindingsHCL := gcpSecretRenderBindingsFromData(v)
		log.Printf("[DEBUG] Rendered GCP Secrets backend roleset bindings HCL:\n%s", bindingsHCL)
		data["bindings"] = bindingsHCL
	}
}

func gcpSecretRolesetExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return secret != nil, nil
}

func gcpSecretRolesetPath(backend, roleset string) string {
	return strings.Trim(backend, "/") + "/roleset/" + strings.Trim(roleset, "/")
}

func gcpSecretRolesetBackendFromPath(path string) (string, error) {
	if !gcpSecretRolesetBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := gcpSecretRolesetBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func gcpSecretRoleSetdRolesetNameFromPath(path string) (string, error) {
	if !gcpSecretRolesetNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no roleset found")
	}
	res := gcpSecretRolesetNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

var (
	gcpSecretStaticAccountBackendFromPathRegex = regexp.MustCompile("^(.+)/static-account/.+$")
	gcpSecretStaticAccountNameFromPathRegex    = regexp.MustCompile("^.+/static-account/(.+)$")
)

func gcpSecretStaticAccountResource() *schema.Resource {
	return &schema.Resource{
		Create: gcpSecretStaticAccountCreate,
		Read:   gcpSecretStaticAccountRead,
		Update: gcpSecretStaticAccountUpdate,
		Delete: gcpSecretStaticAccountDelete,
		Exists: gcpSecretStaticAccountExists,
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
			"static_account": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the Static Account to create",
				ForceNew:    true,
			},
			"secret_type": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "Type of secret generated for this static account. Defaults to `access_token`. Accepted values: `access_token`, `service_account_key`",
			},
			"service_account_email": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Email of the GCP service account.",
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
				Optional: true,
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
			"service_account_project": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Project of the GCP Service Account managed by this static account",
			},
		},
	}
}

func gcpSecretStaticAccountCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	staticAccount := d.Get("static_account").(string)

	path := gcpSecretStaticAccountPath(backend, staticAccount)

	log.Printf("[DEBUG] Writing GCP Secrets backend static account %q", path)

	data := map[string]interface{}{}
	gcpSecretStaticAccountUpdateFields(d, data)
	d.SetId(path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		d.SetId("")
		return fmt.Errorf("Error writing GCP Secrets backend static account %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote GCP Secrets backend static account %q", path)

	return gcpSecretStaticAccountRead(d, meta)
}

func gcpSecretStaticAccountRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	backend, err := gcpSecretStaticAccountBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for GCP secrets backend static account: %s", path, err)
	}

	staticAccount, err := gcpSecretRoleSetdStaticAccountNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for GCP Secrets backend static account: %s", path, err)
	}

	log.Printf("[DEBUG] Reading GCP Secrets backend static account %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading GCP Secrets backend static account %q: %s", path, err)
	}

	log.Printf("[DEBUG] Read GCP Secrets backend static account %q", path)
	if resp == nil {
		log.Printf("[WARN] GCP Secrets backend static account %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set("backend", backend)
	d.Set("static_account", staticAccount)

	for _, k := range []string{"secret_type", "token_scopes", "service_account_email", "service_account_project"} {
		v, ok := resp.Data[k]
		if ok {
			if err := d.Set(k, v); err != nil {
				return fmt.Errorf("error reading %s for GCP Secrets backend static account %q: %q", k, path, err)
			}
		}
	}

	var binding interface{}
	if v, ok := resp.Data["bindings"]; ok && v != "" {
		binding = gcpSecretFlattenBinding(v)
	} else {
		binding = gcpSecretFlattenBinding(nil)
	}
	if err := d.Set("binding", binding); err != nil {
		return fmt.Errorf("error reading %s for GCP Secrets backend static account %q", "binding", path)
	}

	return nil
}

func gcpSecretStaticAccountUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	data := map[string]interface{}{}
	gcpSecretStaticAccountUpdateFields(d, data)

	log.Printf("[DEBUG] Updating GCP Secrets backend static account %q", path)

	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("Error updating GCP Secrets backend static account %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated GCP Secrets backend static account %q", path)

	return gcpSecretStaticAccountRead(d, meta)
}

func gcpSecretStaticAccountDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting GCP secrets backend static account %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting GCP secrets backend static account %q", path)
	}
	log.Printf("[DEBUG] Deleted GCP secrets backend static account %q", path)

	return nil
}

func gcpSecretStaticAccountUpdateFields(d *schema.ResourceData, data map[string]interface{}) {
	if v, ok := d.GetOk("service_account_email"); ok {
		data["service_account_email"] = v.(string)
	}

	if v, ok := d.GetOk("secret_type"); ok {
		data["secret_type"] = v.(string)
	}

	if v, ok := d.GetOk("token_scopes"); ok && d.Get("secret_type").(string) == "access_token" {
		data["token_scopes"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("binding"); ok {
		bindingsHCL := gcpSecretRenderBindingsFromData(v)
		log.Printf("[DEBUG] Rendered GCP Secrets backend static account bindings HCL:\n%s", bindingsHCL)
		data["bindings"] = bindingsHCL
	} else {
		data["bindings"] = ""
	}
}

func gcpSecretStaticAccountExists(d *schema.ResourceData, meta interface{}) (bool, error) {
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

func gcpSecretStaticAccountPath(backend, staticAccount string) string {
	return strings.Trim(backend, "/") + "/static-account/" + strings.Trim(staticAccount, "/")
}

func gcpSecretStaticAccountBackendFromPath(path string) (string, error) {
	if !gcpSecretStaticAccountBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := gcpSecretStaticAccountBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func gcpSecretRoleSetdStaticAccountNameFromPath(path string) (string, error) {
	if !gcpSecretStaticAccountNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no static account found")
	}
	res := gcpSecretStaticAccountNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

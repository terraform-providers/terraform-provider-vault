package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

const gcpAuthType string = "gcp"

func gcpAuthBackendResource() *schema.Resource {
	return &schema.Resource{

		Create: gcpAuthBackendWrite,
		Update: gcpAuthBackendUpdate,
		Read:   gcpAuthBackendRead,
		Delete: gcpAuthBackendDelete,
		Exists: gcpAuthBackendExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"credentials": {
				Type:         schema.TypeString,
				StateFunc:    NormalizeCredentials,
				ValidateFunc: ValidateCredentials,
				Sensitive:    true,
				Optional:     true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"client_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"private_key_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"project_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"client_email": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"path": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "gcp",
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"local": {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Description: "Specifies if the auth method is local only",
			},
		},
	}
}

func ValidateCredentials(configI interface{}, k string) ([]string, []error) {
	credentials := configI.(string)
	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(credentials), &dataMap)
	if err != nil {
		return nil, []error{err}
	}
	return nil, nil
}

func NormalizeCredentials(configI interface{}) string {
	credentials := configI.(string)

	dataMap := map[string]interface{}{}
	err := json.Unmarshal([]byte(credentials), &dataMap)
	if err != nil {
		// The validate function should've taken care of this.
		log.Printf("[ERROR] Invalid JSON data in vault_gcp_auth_backend: %s", err)
		return ""
	}

	ret, err := json.Marshal(dataMap)
	if err != nil {
		// Should never happen.
		log.Printf("[ERROR] Problem normalizing JSON for vault_gcp_auth_backend: %s", err)
		return credentials
	}

	return string(ret)
}

func gcpAuthBackendConfigPath(path string) string {
	return "auth/" + strings.Trim(path, "/") + "/config"
}

func gcpAuthBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	authType := gcpAuthType
	path := d.Get("path").(string)
	desc := d.Get("description").(string)
	local := d.Get("local").(bool)

	log.Printf("[DEBUG] Enabling gcp auth backend %q", path)
	err := client.Sys().EnableAuthWithOptions(path, &api.EnableAuthOptions{
		Type:        authType,
		Description: desc,
		Local:       local,
	})
	if err != nil {
		return fmt.Errorf("error enabling gcp auth backend %q: %s", path, err)
	}
	log.Printf("[DEBUG] Enabled gcp auth backend %q", path)

	d.SetId(path)

	return gcpAuthBackendUpdate(d, meta)
}

func gcpAuthBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := gcpAuthBackendConfigPath(d.Id())
	data := map[string]interface{}{}

	if v, ok := d.GetOk("credentials"); ok {
		data["credentials"] = v.(string)
	}

	log.Printf("[DEBUG] Writing gcp config %q", path)
	_, err := client.Logical().Write(path, data)

	if err != nil {
		d.SetId("")
		return fmt.Errorf("error writing gcp config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Wrote gcp config %q", path)

	return gcpAuthBackendRead(d, meta)
}

func gcpAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := gcpAuthBackendConfigPath(d.Id())

	log.Printf("[DEBUG] Reading gcp auth backend config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading gcp auth backend config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read gcp auth backend config %q", path)

	if resp == nil {
		log.Printf("[WARN] gcp auth backend config %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	d.Set("private_key_id", resp.Data["private_key_id"])
	d.Set("client_id", resp.Data["client_id"])
	d.Set("project_id", resp.Data["project_id"])
	d.Set("client_email", resp.Data["client_email"])
	d.Set("local", resp.Data["local"])
	d.Set("path", d.Id())
	return nil
}

func gcpAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting gcp auth backend %q", path)
	err := client.Sys().DisableAuth(path)
	if err != nil {
		return fmt.Errorf("error deleting gcp auth backend %q: %q", path, err)
	}
	log.Printf("[DEBUG] Deleted gcp auth backend %q", path)

	return nil
}

func gcpAuthBackendExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	path := gcpAuthBackendConfigPath(d.Id())

	log.Printf("[DEBUG] Checking if gcp auth backend %q exists", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking for existence of gcp config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if gcp auth backend %q exists", path)

	return resp != nil, nil
}

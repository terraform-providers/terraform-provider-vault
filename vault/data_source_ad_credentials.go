package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func adAccessCredentialsDataSource() *schema.Resource {
	return &schema.Resource{
		Read: readCredsResource,
		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "AD Secret Backend to read credentials from.",
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role.",
			},
			"current_password": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Password for the service account.",
				Sensitive:   true,
			},
			"last_password": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Last known password for the service account.",
				Sensitive:   true,
			},
			"username": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the service account.",
			},
		},
	}
}

func readCredsResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	backend := d.Get("backend").(string)
	role := d.Get("role").(string)
	path := fmt.Sprintf("%s/creds/%s", backend, role)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	log.Printf("[DEBUG] Read %q from Vault", path)

	if secret == nil {
		return fmt.Errorf("no role found at %q", path)
	}

	currentPassword := secret.Data["current_password"].(string)
	if currentPassword == "" {
		return fmt.Errorf("current_password is not set in response")
	}

	username := secret.Data["username"].(string)
	if username == "" {
		return fmt.Errorf("username is not set in response")
	}

	// When first set this could be empty.
	if lastPassword, ok := secret.Data["last_password"].(string); ok {
		d.Set("last_password", lastPassword)
	}

	d.SetId(username)
	d.Set("username", username)
	d.Set("current_password", currentPassword)

	return nil
}

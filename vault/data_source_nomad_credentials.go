package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func nomadAccessCredentialsDataSource() *schema.Resource {
	return &schema.Resource{
		Read: readNomadCredsResource,
		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Nomad secret backend to generate tokens from.",
			},
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the role.",
			},
			"accessor_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The public identifier for a specific token. It can be used to look up information about a token or to revoke a token.",
			},
			"secret_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Used to make requests to Nomad and should be kept private.",
				Sensitive:   true,
			},
		},
	}
}

func readNomadCredsResource(d *schema.ResourceData, meta interface{}) error {
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

	accessorID := secret.Data["accessor_id"].(string)
	if accessorID == "" {
		return fmt.Errorf("accessor_id is not set in response")
	}

	secretID := secret.Data["secret_id"].(string)
	if secretID == "" {
		return fmt.Errorf("secret_id is not set in response")
	}

	d.SetId(accessorID)
	d.Set("accessor_id", accessorID)
	d.Set("secret_id", secretID)

	return nil
}

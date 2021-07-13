package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	"github.com/hashicorp/vault/api"
)

func genericKeyListDataSource() *schema.Resource {
	return &schema.Resource{
		Read: genericKeyListDataSourceRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Full path from which a secret will be read.",
			},

			"version": {
				Type:     schema.TypeInt,
				Required: false,
				Optional: true,
				Default:  latestSecretVersion,
			},

			"data_json": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON-encoded secret data read from Vault.",
				Sensitive:   true,
			},

			"data": {
				Type: schema.TypeSet,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Computed:    true,
				Description: "Map of strings read from Vault.",
				Sensitive:   true,
			},

			"lease_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by vault.",
			},

			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds relative to the time in lease_start_time.",
			},

			"lease_start_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time at which the lease was read, using the clock of the system where Terraform was running",
			},

			"lease_renewable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},
		},
	}
}

func genericKeyListDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)

	secretVersion := d.Get("version").(int)
	log.Printf("[DEBUG] Reading %s %d from Vault", path, secretVersion)

	mountPath, v2, err := isKVv2(path, client)
	if err != nil {
		return fmt.Errorf("error reading KV version: %s", err)
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, "metadata")
	}

	secret, err := client.Logical().List(path)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	if secret == nil {
		return fmt.Errorf("no secret found at %q", path)
	}

	d.SetId(path)

	jsonDataBytes, _ := json.Marshal(secret.Data)
	d.Set("data_json", string(jsonDataBytes))

	dataList := make([]string, 0)
	for k, _ := range secret.Data {
		dataList = append(dataList, k)
	}

	log.Printf("[DEBUG] %s", dataList)

	d.Set("data", dataList)

	d.Set("lease_id", secret.LeaseID)
	d.Set("lease_duration", secret.LeaseDuration)
	d.Set("lease_start_time", time.Now().Format("RFC3339"))
	d.Set("lease_renewable", secret.Renewable)
	return nil
}

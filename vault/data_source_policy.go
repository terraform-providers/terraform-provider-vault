package vault

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func policyDataSource() *schema.Resource {
	return &schema.Resource{
		Read: policyDataSourceRead,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the policy",
			},

			"policy": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The policy document",
			},
		},
	}
}

func policyDataSourceRead (d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	targetPolicy := d.Get("name").(string)

	policies, err := client.Sys().ListPolicies()
	if err != nil {
		return fmt.Errorf("error listing policies from Vault: %s", err)
	}

	for _, policyName := range policies {
		if policyName == targetPolicy {
			policy, err := client.Sys().GetPolicy(policyName)
			if err != nil {
				return fmt.Errorf("error reading policy %s from Vault: %s", policyName, err)
			}

			d.Set("name", policyName)
			d.Set("policy", policy)
			return nil
		}
	}

	// If we fell out here then we didn't find our policy in the list.
	return nil
}

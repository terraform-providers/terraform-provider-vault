package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/hashicorp/vault/api"
)

func authMountTuneSchema() *schema.Schema {
	return &schema.Schema{
		Type:       schema.TypeSet,
		Optional:   true,
		Computed:   true,
		MaxItems:   1,
		ConfigMode: schema.SchemaConfigModeAttr,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"default_lease_ttl": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies the default time-to-live duration. This overrides the global default. A value of 0 is equivalent to the system default TTL",
					ValidateFunc: validateDuration,
				},
				"max_lease_ttl": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies the maximum time-to-live duration. This overrides the global default. A value of 0 are equivalent and set to the system max TTL.",
					ValidateFunc: validateDuration,
				},
				"audit_non_hmac_request_keys": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the request data object.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"audit_non_hmac_response_keys": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "Specifies the list of keys that will not be HMAC'd by audit devices in the response data object.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"listing_visibility": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies whether to show this mount in the UI-specific listing endpoint. Valid values are \"unauth\" or \"hidden\". If not set, behaves like \"hidden\".",
					ValidateFunc: validation.StringInSlice([]string{"unauth", "hidden"}, false),
					Default:      "hidden",
				},
				"passthrough_request_headers": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "List of headers to whitelist and pass from the request to the backend.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"allowed_response_headers": {
					Type:        schema.TypeList,
					Optional:    true,
					Description: "List of headers to whitelist and allowing a plugin to include them in the response.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"token_type": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Specifies the type of tokens that should be returned by the mount.",
					ValidateFunc: validation.StringInSlice([]string{"default-service", "default-batch", "service", "batch"}, false),
				},
			},
		},
	}
}

func authMountInfoGet(client *api.Client, path string) (*api.AuthMount, error) {
	auths, err := client.Sys().ListAuth()
	if err != nil {
		return nil, fmt.Errorf("error reading from auth mounts: %s", err)
	}

	authMount := auths[strings.Trim(path, "/")+"/"]
	if authMount == nil {
		return nil, fmt.Errorf("auth mount %s not present", path)
	}
	return authMount, nil
}

func authMountTune(client *api.Client, path string, configured interface{}) error {
	tune := expandAuthMethodTune(configured.(*schema.Set).List())

	err := client.Sys().TuneMount(path, tune)
	if err != nil {
		return err
	}
	return nil
}

func authMountTuneGet(client *api.Client, path string) (map[string]interface{}, error) {
	tune, err := client.Sys().MountConfig(path)
	if err != nil {
		log.Printf("[ERROR] Error when reading tune config from path %q: %s", path+"/tune", err)
		return nil, err
	}

	return flattenAuthMethodTune(tune), nil
}

func authMountDisable(client *api.Client, path string) error {
	log.Printf("[DEBUG] Disabling auth mount config from '%q'", path)
	err := client.Sys().DisableAuth(path)
	if err != nil {
		return fmt.Errorf("error disabling auth mount from '%q': %s", path, err)
	}
	log.Printf("[INFO] Disabled auth mount from '%q'", path)

	return nil
}

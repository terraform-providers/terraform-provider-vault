package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func AuthBackendResource() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,

		Create: authBackendWrite,
		Delete: authBackendDelete,
		Read:   authBackendRead,
		Update: authBackendUpdate,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		MigrateState: resourceAuthBackendMigrateState,

		Schema: map[string]*schema.Schema{
			"type": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the auth backend",
			},

			"path": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				ForceNew:     true,
				Description:  "path to mount the backend. This defaults to the type.",
				ValidateFunc: validateNoTrailingSlash,
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return old+"/" == new || new+"/" == old
				},
			},

			"description": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"local": {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Description: "Specifies if the auth method is local only",
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The accessor of the auth backend",
			},

			"tune": authMountTuneSchema(),
		},
	}
}

func authBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	mountType := d.Get("type").(string)
	path := d.Get("path").(string)

	options := &api.EnableAuthOptions{
		Type:        mountType,
		Description: d.Get("description").(string),
		Local:       d.Get("local").(bool),
	}

	if path == "" {
		path = mountType
	}

	tunes := d.Get("tune").(*schema.Set)
	if tunes.Len() > 0 {
		tune := tunes.List()[0].(map[string]interface{})

		options.Config = api.AuthConfigInput{
			DefaultLeaseTTL:   tune["default_lease_ttl"].(string),
			MaxLeaseTTL:       tune["max_lease_ttl"].(string),
			ListingVisibility: tune["listing_visibility"].(string),
		}

	}

	if err := client.Sys().EnableAuthWithOptions(path, options); err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return authBackendRead(d, meta)
}

func authBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Deleting auth %s from Vault", path)

	if err := client.Sys().DisableAuth(path); err != nil {
		return fmt.Errorf("error disabling auth from Vault: %s", err)
	}

	return nil
}

func authBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	targetPath := d.Id()

	auths, err := client.Sys().ListAuth()

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	for path, auth := range auths {
		path = strings.TrimSuffix(path, "/")
		if path == targetPath {
			d.Set("type", auth.Type)
			d.Set("path", path)
			d.Set("description", auth.Description)
			d.Set("local", auth.Local)
			d.Set("accessor", auth.Accessor)

			tunes := d.Get("tune").(*schema.Set)
			var tune map[string]interface{}
			if tunes.Len() > 0 {
				t := tunes.List()[0]
				tunes.Remove(t)

				tune = t.(map[string]interface{})
			} else {
				tune = make(map[string]interface{})
			}

			tune["default_lease_ttl"] = fmt.Sprintf("%ds", auth.Config.DefaultLeaseTTL)
			tune["max_lease_ttl"] = fmt.Sprintf("%ds", auth.Config.MaxLeaseTTL)
			tune["listing_visibility"] = auth.Config.ListingVisibility

			tunes.Add(tune)
			if err := d.Set("tune", tunes); err != nil {
				return err
			}

			return nil
		}
	}

	// If we fell out here then we didn't find our Auth in the list.
	d.SetId("")
	return nil
}

func authBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Updating auth %s in Vault", path)

	if d.HasChange("tune") {
		log.Printf("[INFO] Auth '%q' tune configuration changed", d.Id())
		if raw, ok := d.GetOk("tune"); ok {
			backendType := d.Get("type")
			log.Printf("[DEBUG] Writing %s auth tune to '%q'", backendType, path)

			if err := authMountTune(client, "auth/"+path, raw); err != nil {
				return err
			}

			log.Printf("[INFO] Written %s auth tune to '%q'", backendType, path)
			d.SetPartial("tune")
		}
	}

	return authBackendRead(d, meta)
}

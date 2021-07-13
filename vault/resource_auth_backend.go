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
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"default_lease_ttl_seconds": {
				Type:          schema.TypeInt,
				Required:      false,
				Optional:      true,
				Computed:      true,
				ForceNew:      true,
				ConflictsWith: []string{"tune.0.default_lease_ttl"},
				Deprecated:    "Use the tune configuration block to avoid forcing creation of new resource on an update",
				Description:   "Default lease duration in seconds",
			},

			"max_lease_ttl_seconds": {
				Type:          schema.TypeInt,
				Required:      false,
				Optional:      true,
				Computed:      true,
				ForceNew:      true,
				ConflictsWith: []string{"tune.0.max_lease_ttl"},
				Deprecated:    "Use the tune configuration block to avoid forcing creation of new resource on an update",
				Description:   "Maximum possible lease duration in seconds",
			},

			"listing_visibility": {
				Type:          schema.TypeString,
				ForceNew:      true,
				Optional:      true,
				Computed:      true,
				ConflictsWith: []string{"tune.0.listing_visibility"},
				Deprecated:    "Use the tune configuration block to avoid forcing creation of new resource on an update",
				Description:   "Specifies whether to show this mount in the UI-specific listing endpoint",
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
		Config: api.AuthConfigInput{
			DefaultLeaseTTL:   fmt.Sprintf("%ds", d.Get("default_lease_ttl_seconds")),
			MaxLeaseTTL:       fmt.Sprintf("%ds", d.Get("max_lease_ttl_seconds")),
			ListingVisibility: d.Get("listing_visibility").(string),
		},
		Local: d.Get("local").(bool),
	}

	if path == "" {
		path = mountType
	}

	log.Printf("[DEBUG] Writing auth %q to Vault", path)

	if err := client.Sys().EnableAuthWithOptions(path, options); err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(path)

	return authBackendUpdate(d, meta)
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
			d.Set("default_lease_ttl_seconds", auth.Config.DefaultLeaseTTL)
			d.Set("max_lease_ttl_seconds", auth.Config.MaxLeaseTTL)
			d.Set("listing_visibility", auth.Config.ListingVisibility)
			d.Set("local", auth.Local)
			d.Set("accessor", auth.Accessor)
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

			err := authMountTune(client, "auth/"+path, raw)
			if err != nil {
				return nil
			}

			log.Printf("[INFO] Written %s auth tune to '%q'", backendType, path)
			d.SetPartial("tune")
		}
	}

	return authBackendRead(d, meta)
}

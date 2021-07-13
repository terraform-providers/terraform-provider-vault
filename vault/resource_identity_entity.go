package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

const identityEntityPath = "/identity/entity"

func identityEntityResource() *schema.Resource {
	return &schema.Resource{
		Create: identityEntityCreate,
		Update: identityEntityUpdate,
		Read:   identityEntityRead,
		Delete: identityEntityDelete,
		Exists: identityEntityExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the entity.",
				Optional:    true,
				Computed:    true,
			},

			"metadata": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Metadata to be associated with the entity.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},

			"policies": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Policies to be tied to the entity.",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return d.Get("external_policies").(bool)
				},
			},

			"external_policies": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Manage policies externally through `vault_identity_entity_policies`.",
			},

			"disabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Whether the entity is disabled. Disabled entities' associated tokens cannot be used, but are not revoked.",
			},
		},
	}
}

func identityEntityUpdateFields(d *schema.ResourceData, data map[string]interface{}, create bool) {
	if create {
		if name, ok := d.GetOk("name"); ok {
			data["name"] = name
		}

		if externalPolicies, ok := d.GetOk("external_policies"); !(ok && externalPolicies.(bool)) {
			if policies, ok := d.GetOk("policies"); ok {
				data["policies"] = policies.(*schema.Set).List()
			}
		}

		if metadata, ok := d.GetOk("metadata"); ok {
			data["metadata"] = metadata
		}

		if disabled, ok := d.GetOk("disabled"); ok {
			data["disabled"] = disabled
		}
	} else {
		if d.HasChanges("name", "external_policies", "policies", "metadata", "disabled") {
			data["name"] = d.Get("name")
			data["metadata"] = d.Get("metadata")
			data["disabled"] = d.Get("disabled")
			data["policies"] = d.Get("policies").(*schema.Set).List()

			// Edge case where if external_policies is true, no policies
			// should be configured on the entity.
			data["external_policies"] = d.Get("external_policies").(bool)
			if data["external_policies"].(bool) {
				data["policies"] = nil
			}
		}
	}
}

func identityEntityCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	path := identityEntityPath

	data := map[string]interface{}{
		"name": name,
	}

	identityEntityUpdateFields(d, data, true)

	resp, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error writing IdentityEntity to %q: %s", name, err)
	}

	if resp == nil {
		path := identityEntityNamePath(name)
		entityMsg := "Unable to determine entity id."

		if entity, err := client.Logical().Read(path); err == nil {
			entityMsg = fmt.Sprintf("Entity resource ID %q may be imported.", entity.Data["id"])
		}

		return fmt.Errorf("Identity Entity %q already exists. %s", name, entityMsg)
	} else {
		log.Printf("[DEBUG] Wrote IdentityEntity %q", name)
	}

	d.SetId(resp.Data["id"].(string))

	return identityEntityRead(d, meta)
}

func identityEntityUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityEntity %q", id)
	path := identityEntityIDPath(id)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := map[string]interface{}{}

	identityEntityUpdateFields(d, data, false)

	_, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error updating IdentityEntity %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityEntity %q", id)

	return identityEntityRead(d, meta)
}

func identityEntityRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	resp, err := readIdentityEntity(client, id)
	if err != nil {
		// We need to check if the secret_id has expired
		if util.IsExpiredTokenErr(err) {
			return nil
		}
		return fmt.Errorf("error reading IdentityEntity %q: %s", id, err)
	}
	log.Printf("[DEBUG] Read IdentityEntity %s", id)
	if resp == nil {
		log.Printf("[WARN] IdentityEntity %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	for _, k := range []string{"name", "metadata", "disabled", "policies"} {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on IdentityEntity %q: %s", k, id, err)
		}
	}
	return nil
}

func identityEntityDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	path := identityEntityIDPath(id)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	log.Printf("[DEBUG] Deleting IdentityEntitty %q", id)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error IdentityEntity %q", id)
	}
	log.Printf("[DEBUG] Deleted IdentityEntity %q", id)

	return nil
}

func identityEntityExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	id := d.Id()

	path := identityEntityIDPath(id)
	key := id

	// use the name if no ID is set
	if len(id) == 0 {
		key = d.Get("name").(string)
		path = identityEntityNamePath(key)
	}

	log.Printf("[DEBUG] Checking if IdentityEntity %q exists", key)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if IdentityEntity %q exists: %s", key, err)
	}
	log.Printf("[DEBUG] Checked if IdentityEntity %q exists", key)

	return resp != nil, nil
}

func identityEntityNamePath(name string) string {
	return fmt.Sprintf("%s/name/%s", identityEntityPath, name)
}

func identityEntityIDPath(id string) string {
	return fmt.Sprintf("%s/id/%s", identityEntityPath, id)
}

func readIdentityEntityPolicies(client *api.Client, entityID string) ([]interface{}, error) {
	resp, err := readIdentityEntity(client, entityID)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("error IdentityEntity %s does not exist", entityID)
	}

	if v, ok := resp.Data["policies"]; ok && v != nil {
		return v.([]interface{}), nil
	}
	return make([]interface{}, 0), nil
}

// May return nil if entity does not exist
func readIdentityEntity(client *api.Client, entityID string) (*api.Secret, error) {
	path := identityEntityIDPath(entityID)
	log.Printf("[DEBUG] Reading Entity %s from %q", entityID, path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return resp, fmt.Errorf("failed reading IdentityEntity %s from %s", entityID, path)
	}
	return resp, nil
}

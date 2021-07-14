package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

const identityGroupPath = "/identity/group"

func identityGroupResource() *schema.Resource {
	return &schema.Resource{
		Create: identityGroupCreate,
		Update: identityGroupUpdate,
		Read:   identityGroupRead,
		Delete: identityGroupDelete,
		Exists: identityGroupExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Description: "Name of the group.",
				Optional:    true,
				Computed:    true,
			},

			"type": {
				Type:        schema.TypeString,
				Description: "Type of the group, internal or external. Defaults to internal.",
				ForceNew:    true,
				Optional:    true,
				Default:     "internal",
			},

			"metadata": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Metadata to be associated with the group.",
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
				Description: "Policies to be tied to the group.",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return d.Get("external_policies").(bool)
				},
			},

			"external_policies": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Manage policies externally through `vault_identity_group_policies`, allows using group ID in assigned policies.",
			},

			"member_group_ids": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Group IDs to be assigned as group members.",
				// Suppress the diff if group type is "external" because we cannot manage
				// group members
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					if d.Get("type").(string) == "external" {
						return true
					}
					return false
				},
			},

			"member_entity_ids": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Entity IDs to be assigned as group members.",
				// Suppress the diff if group type is "external" because we cannot manage
				// group members
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					if d.Get("type").(string) == "external" || d.Get("external_member_entity_ids").(bool) == true {
						return true
					}
					return false
				},
			},

			"external_member_entity_ids": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Manage member entities externally through `vault_identity_group_policies_member_entity_ids`",
			},
		},
	}
}

func identityGroupUpdateFields(d *schema.ResourceData, data map[string]interface{}, create bool) error {
	if create {
		if name, ok := d.GetOk("name"); ok {
			data["name"] = name
		}

		if externalPolicies, ok := d.GetOk("external_policies"); !(ok && externalPolicies.(bool)) {
			data["policies"] = d.Get("policies").(*schema.Set).List()
		}

		// Member groups and entities can't be set for external groups
		if d.Get("type").(string) == "internal" {
			data["member_group_ids"] = d.Get("member_group_ids").(*schema.Set).List()

			if externalMemberEntityIds, ok := d.GetOk("external_member_entity_ids"); !(ok && externalMemberEntityIds.(bool)) {
				data["member_entity_ids"] = d.Get("member_entity_ids").(*schema.Set).List()
			}
		}

		if metadata, ok := d.GetOk("metadata"); ok {
			data["metadata"] = metadata
		}
	} else {
		if d.HasChanges("name", "external_policies", "policies", "metadata", "member_entity_ids", "member_group_ids") {
			data["name"] = d.Get("name")
			data["metadata"] = d.Get("metadata")
			data["policies"] = d.Get("policies").(*schema.Set).List()
			data["member_entity_ids"] = d.Get("member_entity_ids").(*schema.Set).List()
			data["member_group_ids"] = d.Get("member_group_ids").(*schema.Set).List()

			// Edge case where if external_policies is true, no policies
			// should be configured on the entity.
			data["external_policies"] = d.Get("external_policies").(bool)
			if data["external_policies"].(bool) {
				data["policies"] = nil
			}
			// if external_member_entity_ids is true, member_entity_ids will be nil
			data["external_member_entity_ids"] = d.Get("external_member_entity_ids").(bool)
			if data["external_member_entity_ids"].(bool) {
				data["member_entity_ids"] = nil
			}
		}
	}

	return nil
}

func identityGroupCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)
	typeValue := d.Get("type").(string)

	path := identityGroupPath

	data := map[string]interface{}{
		"type": typeValue,
	}

	if err := identityGroupUpdateFields(d, data, true); err != nil {
		return fmt.Errorf("error writing IdentityGroup to %q: %s", name, err)
	}

	resp, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error writing IdentityGroup to %q: %s", name, err)
	}
	log.Printf("[DEBUG] Wrote IdentityGroup %q", resp.Data["name"])

	d.SetId(resp.Data["id"].(string))

	return identityGroupRead(d, meta)
}

func identityGroupUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	log.Printf("[DEBUG] Updating IdentityGroup %q", id)
	path := identityGroupIDPath(id)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	data := map[string]interface{}{}

	if err := identityGroupUpdateFields(d, data, false); err != nil {
		return fmt.Errorf("error updating IdentityGroup %q: %s", id, err)
	}

	_, err := client.Logical().Write(path, data)

	if err != nil {
		return fmt.Errorf("error updating IdentityGroup %q: %s", id, err)
	}
	log.Printf("[DEBUG] Updated IdentityGroup %q", id)

	return identityGroupRead(d, meta)
}

func identityGroupRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	resp, err := readIdentityGroup(client, id)
	if err != nil {
		// We need to check if the secret_id has expired
		if util.IsExpiredTokenErr(err) {
			return nil
		}
		return fmt.Errorf("error reading IdentityGroup %q: %s", id, err)
	}
	log.Printf("[DEBUG] Read IdentityGroup %s", id)
	if resp == nil {
		log.Printf("[WARN] IdentityGroup %q not found, removing from state", id)
		d.SetId("")
		return nil
	}

	readFields := []string{"name", "type", "metadata", "member_entity_ids", "member_group_ids", "policies"}

	for _, k := range readFields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return fmt.Errorf("error setting state key \"%s\" on IdentityGroup %q: %s", k, id, err)
		}
	}
	return nil
}

func identityGroupDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	id := d.Id()

	path := identityGroupIDPath(id)

	vaultMutexKV.Lock(path)
	defer vaultMutexKV.Unlock(path)

	log.Printf("[DEBUG] Deleting IdentityGroup %q", id)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error IdentityGroup %q", id)
	}
	log.Printf("[DEBUG] Deleted IdentityGroup %q", id)

	return nil
}

func identityGroupExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	id := d.Id()
	key := id

	if len(id) == 0 {
		return false, nil
	} else {
		key = d.Get("name").(string)
	}

	log.Printf("[DEBUG] Checking if IdentityGroup %q exists", key)
	resp, err := readIdentityGroup(client, id)
	if err != nil {
		return true, fmt.Errorf("error checking if IdentityGroup %q exists: %s", key, err)
	}
	log.Printf("[DEBUG] Checked if IdentityGroup %q exists", key)
	return resp != nil, nil
}

func identityGroupIDPath(id string) string {
	return fmt.Sprintf("%s/id/%s", identityGroupPath, id)
}

func readIdentityGroupPolicies(client *api.Client, groupID string) ([]interface{}, error) {
	resp, err := readIdentityGroup(client, groupID)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("error IdentityGroup %s does not exist", groupID)
	}

	if v, ok := resp.Data["policies"]; ok && v != nil {
		return v.([]interface{}), nil
	}
	return make([]interface{}, 0), nil
}

func readIdentityGroupMemberEntityIds(client *api.Client, groupID string) ([]interface{}, error) {
	resp, err := readIdentityGroup(client, groupID)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("error IdentityGroup %s does not exist", groupID)
	}

	if v, ok := resp.Data["member_entity_ids"]; ok && v != nil {
		return v.([]interface{}), nil
	}
	return make([]interface{}, 0), nil
}

// This function may return `nil` for the IdentityGroup if it does not exist
func readIdentityGroup(client *api.Client, groupID string) (*api.Secret, error) {
	path := identityGroupIDPath(groupID)
	log.Printf("[DEBUG] Reading IdentityGroup %s from %q", groupID, path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return resp, fmt.Errorf("failed reading IdentityGroup %s from %s", groupID, path)
	}
	return resp, nil
}

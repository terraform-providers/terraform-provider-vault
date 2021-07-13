package vault

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

var oktaAuthType = "okta"

func oktaAuthBackendResource() *schema.Resource {
	return &schema.Resource{
		Create: oktaAuthBackendWrite,
		Delete: oktaAuthBackendDelete,
		Read:   oktaAuthBackendRead,
		Update: oktaAuthBackendUpdate,

		Schema: map[string]*schema.Schema{

			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "path to mount the backend",
				Default:     oktaAuthType,
				ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
					value := v.(string)
					if strings.HasSuffix(value, "/") {
						errs = append(errs, errors.New("cannot write to a path ending in '/'"))
					}
					return
				},
			},

			"description": {
				Type:        schema.TypeString,
				Required:    false,
				ForceNew:    true,
				Optional:    true,
				Description: "The description of the auth backend",
			},

			"organization": {
				Type:        schema.TypeString,
				Required:    true,
				Optional:    false,
				Description: "The Okta organization. This will be the first part of the url https://XXX.okta.com.",
			},

			"token": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The Okta API token. This is required to query Okta for user group membership. If this is not supplied only locally configured groups will be enabled.",
				Sensitive:   true,
			},

			"base_url": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The Okta url. Examples: oktapreview.com, okta.com (default)",
			},

			"bypass_okta_mfa": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "When true, requests by Okta for a MFA check will be bypassed. This also disallows certain status checks on the account, such as whether the password is expired.",
			},

			"ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Duration after which authentication will be expired",
			},

			"max_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Maximum duration after which authentication will be expired",
			},

			"group": {
				Type:       schema.TypeSet,
				Required:   false,
				Optional:   true,
				Computed:   true,
				ConfigMode: schema.SchemaConfigModeAttr,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"group_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Name of the Okta group",
							ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
								value := v.(string)
								// No comma as it'll become part of a comma separate list
								if strings.Contains(value, ",") {
									errs = append(errs, errors.New("group cannot contain ','"))
								}
								return
							},
						},

						"policies": {
							Type:        schema.TypeSet,
							Required:    true,
							Description: "Policies to associate with this group",
							Elem: &schema.Schema{
								Type: schema.TypeString,
								ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
									value := v.(string)
									// No comma as it'll become part of a comma separate list
									if strings.Contains(value, ",") {
										errs = append(errs, errors.New("policy cannot contain ','"))
									}
									return
								},
							},
							Set: schema.HashString,
						},
					},
				},
				Set: resourceOktaGroupHash,
			},

			"user": {
				Type:       schema.TypeSet,
				Required:   false,
				Optional:   true,
				Computed:   true,
				ConfigMode: schema.SchemaConfigModeAttr,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"groups": {
							Type:        schema.TypeSet,
							Required:    true,
							Description: "Groups within the Okta auth backend to associate with this user",
							Elem: &schema.Schema{
								Type: schema.TypeString,
								ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
									value := v.(string)
									// No comma as it'll become part of a comma separate list
									if strings.Contains(value, ",") {
										errs = append(errs, errors.New("group cannot contain ','"))
									}
									return
								},
							},
							Set: schema.HashString,
						},

						"username": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "Name of the user within Okta",
							ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
								value := v.(string)
								if strings.Contains(value, "/") {
									errs = append(errs, errors.New("user cannot contain '/'"))
								}
								return
							},
						},

						"policies": {
							Type:        schema.TypeSet,
							Required:    false,
							Optional:    true,
							Description: "Policies to associate with this user",
							Elem: &schema.Schema{
								Type: schema.TypeString,
								ValidateFunc: func(v interface{}, k string) (ws []string, errs []error) {
									value := v.(string)
									// No comma as it'll become part of a comma separate list
									if strings.Contains(value, ",") {
										errs = append(errs, errors.New("policy cannot contain ','"))
									}
									return
								},
							},
							Set: schema.HashString,
						},
					},
				},
				Set: resourceOktaUserHash,
			},

			"accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The mount accessor related to the auth mount.",
			},
			"tune": authMountTuneSchema(),
		},
	}
}

func oktaAuthBackendWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	authType := oktaAuthType
	desc := d.Get("description").(string)
	path := d.Get("path").(string)

	log.Printf("[DEBUG] Writing auth %s to Vault", authType)
	err := client.Sys().EnableAuthWithOptions(path, &api.EnableAuthOptions{
		Type:        authType,
		Description: desc,
	})

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}
	log.Printf("[INFO] Enabled okta auth backend at '%s'", path)

	d.SetId(path)
	return oktaAuthBackendUpdate(d, meta)
}

func oktaAuthBackendDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()

	log.Printf("[DEBUG] Deleting auth %s from Vault", path)

	err := client.Sys().DisableAuth(path)

	if err != nil {
		return fmt.Errorf("error disabling auth from Vault: %s", err)
	}

	return nil
}

func oktaAuthBackendRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Reading auth %s from Vault", path)

	present, err := isOktaAuthBackendPresent(client, path)

	if err != nil {
		return fmt.Errorf("unable to check auth backends in Vault for path %s: %s", path, err)
	}

	if !present {
		// If we fell out here then we didn't find our Auth in the list.
		d.SetId("")
		return nil
	}

	mount, err := authMountInfoGet(client, path)
	if err != nil {
		return fmt.Errorf("error reading okta oth mount from '%q': %s", path, err)
	}

	log.Printf("[INFO] Reading okta auth tune from '%q/tune'", path)
	rawTune, err := authMountTuneGet(client, oktaTuneEndpoint(path))
	if err != nil {
		return fmt.Errorf("error reading tune information from Vault: %s", err)
	}

	if err := d.Set("tune", []map[string]interface{}{rawTune}); err != nil {
		log.Printf("[ERROR] Error when setting tune config from path '%q/tune' to state: %s", path, err)
		return err
	}

	log.Printf("[INFO] Read okta auth tune from '%q/tune'", path)

	d.Set("accessor", mount.Accessor)

	log.Printf("[DEBUG] Reading groups for mount %s from Vault", path)
	groups, err := oktaReadAllGroups(client, path)
	if err != nil {
		return err
	}
	if err := d.Set("group", groups); err != nil {
		return err
	}

	log.Printf("[DEBUG] Reading users for mount %s from Vault", path)
	users, err := oktaReadAllUsers(client, path)
	if err != nil {
		return err
	}
	if err := d.Set("user", users); err != nil {
		return err
	}

	return nil

}

func oktaAuthBackendUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Updating auth %s in Vault", path)

	configuration := map[string]interface{}{
		"base_url":        d.Get("base_url"),
		"bypass_okta_mfa": d.Get("bypass_okta_mfa"),
		"organization":    d.Get("organization"),
		"token":           d.Get("token"),
	}

	if ttl, ok := d.GetOk("ttl"); ok {
		configuration["ttl"] = ttl
	}

	if maxTtl, ok := d.GetOk("max_ttl"); ok {
		configuration["max_ttl"] = maxTtl
	}

	_, err := client.Logical().Write(oktaConfigEndpoint(path), configuration)
	if err != nil {
		return fmt.Errorf("error updating configuration to Vault for path %s: %s", path, err)
	}

	if d.HasChange("group") {
		oldValue, newValue := d.GetChange("group")

		err = oktaAuthUpdateGroups(d, client, path, oldValue, newValue)
		if err != nil {
			return err
		}
	}

	if d.HasChange("user") {
		oldValue, newValue := d.GetChange("user")

		err = oktaAuthUpdateUsers(d, client, path, oldValue, newValue)
		if err != nil {
			return err
		}
	}

	if d.HasChange("tune") {
		if raw, ok := d.GetOk("tune"); ok {
			log.Printf("[INFO] Writing okta auth tune to '%q'", oktaTuneEndpoint(path))

			err := authMountTune(client, oktaTuneEndpoint(path), raw)
			if err != nil {
				return nil
			}

			d.SetPartial("tune")
		}
	}

	return oktaAuthBackendRead(d, meta)
}

func oktaReadAllGroups(client *api.Client, path string) (*schema.Set, error) {
	groupNames, err := listOktaGroups(client, path)
	if err != nil {
		return nil, fmt.Errorf("unable to list groups from %s in Vault: %s", path, err)
	}

	groups := &schema.Set{F: resourceOktaGroupHash}
	for _, groupName := range groupNames {
		group, err := readOktaGroup(client, path, groupName)
		if err != nil {
			return nil, fmt.Errorf("unable to read group %s from %s in Vault: %s", path, groupName, err)
		}

		policies := &schema.Set{F: schema.HashString}
		for _, v := range group.Policies {
			policies.Add(v)
		}

		m := make(map[string]interface{})
		m["policies"] = policies
		m["group_name"] = group.Name

		groups.Add(m)
	}

	return groups, nil
}

func oktaReadAllUsers(client *api.Client, path string) (*schema.Set, error) {
	userNames, err := listOktaUsers(client, path)
	if err != nil {
		return nil, fmt.Errorf("unable to list groups from %s in Vault: %s", path, err)
	}

	users := &schema.Set{F: resourceOktaUserHash}
	for _, userName := range userNames {
		user, err := readOktaUser(client, path, userName)
		if err != nil {
			return nil, fmt.Errorf("unable to read user %s from %s in Vault: %s", path, userName, err)
		}

		groups := &schema.Set{F: schema.HashString}
		for _, v := range user.Groups {
			groups.Add(v)
		}

		policies := &schema.Set{F: schema.HashString}
		for _, v := range user.Policies {
			policies.Add(v)
		}

		m := make(map[string]interface{})
		m["policies"] = policies
		m["groups"] = groups
		m["username"] = user.Username

		users.Add(m)
	}

	return users, nil
}

func oktaAuthUpdateGroups(d *schema.ResourceData, client *api.Client, path string, oldValue, newValue interface{}) error {

	groupsToDelete := oldValue.(*schema.Set).Difference(newValue.(*schema.Set))
	newGroups := newValue.(*schema.Set).Difference(oldValue.(*schema.Set))

	for _, group := range groupsToDelete.List() {
		groupName := group.(map[string]interface{})["group_name"].(string)
		log.Printf("[DEBUG] Removing Okta group %s from Vault", groupName)
		if err := deleteOktaGroup(client, path, groupName); err != nil {
			return fmt.Errorf("error removing group %s to Vault for path %s: %s", groupName, path, err)
		}
	}

	groups := oldValue.(*schema.Set).Intersection(newValue.(*schema.Set))

	for _, v := range newGroups.List() {
		groupMapping := v.(map[string]interface{})
		groupName := groupMapping["group_name"].(string)

		log.Printf("[DEBUG] Adding Okta group %s to Vault", groupName)

		group := oktaGroup{
			Name:     groupName,
			Policies: util.ToStringArray(groupMapping["policies"].(*schema.Set).List()),
		}

		if err := updateOktaGroup(client, path, group); err != nil {
			return fmt.Errorf("error updating group %s mapping to Vault for path %s: %s", group.Name, path, err)
		}

		groups.Add(v)
	}

	return nil
}

func oktaAuthUpdateUsers(d *schema.ResourceData, client *api.Client, path string, oldValue, newValue interface{}) error {
	usersToDelete := oldValue.(*schema.Set).Difference(newValue.(*schema.Set))
	newUsers := newValue.(*schema.Set).Difference(oldValue.(*schema.Set))

	for _, user := range usersToDelete.List() {
		userName := user.(map[string]interface{})["username"].(string)
		log.Printf("[DEBUG] Removing Okta user %s from Vault", userName)
		if err := deleteOktaUser(client, path, userName); err != nil {
			return fmt.Errorf("error removing user %s mapping to Vault for path %s: %s", userName, path, err)
		}
	}

	users := oldValue.(*schema.Set).Intersection(newValue.(*schema.Set))

	for _, v := range newUsers.List() {
		userMapping := v.(map[string]interface{})
		userName := userMapping["username"].(string)

		log.Printf("[DEBUG] Adding Okta user %s to Vault", userName)

		user := oktaUser{
			Username: userName,
			Policies: util.ToStringArray(userMapping["policies"].(*schema.Set).List()),
			Groups:   util.ToStringArray(userMapping["groups"].(*schema.Set).List()),
		}

		if err := updateOktaUser(client, path, user); err != nil {
			return fmt.Errorf("error updating user %s mapping to Vault for path %s: %s", user.Username, path, err)
		}

		users.Add(v)
	}

	return nil
}

func resourceOktaGroupHash(v interface{}) int {
	m, castOk := v.(map[string]interface{})
	if !castOk {
		return 0
	}
	if v, ok := m["group_name"]; ok {
		return hashcode.String(v.(string))
	}

	return 0
}

func resourceOktaUserHash(v interface{}) int {
	m, castOk := v.(map[string]interface{})
	if !castOk {
		return 0
	}
	if v, ok := m["username"]; ok {
		return hashcode.String(v.(string))
	}

	return 0
}

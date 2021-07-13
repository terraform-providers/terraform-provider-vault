package vault

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/encryption"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

func tokenResource() *schema.Resource {
	return &schema.Resource{
		Create: tokenCreate,
		Read:   tokenRead,
		Update: tokenUpdate,
		Delete: tokenDelete,
		Exists: tokenExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"role_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The token role name.",
			},
			"policies": {
				Type:     schema.TypeSet,
				Required: false,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of policies.",
			},
			"no_parent": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "Flag to create a token without parent.",
			},
			"no_default_policy": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "Flag to disable the default policy.",
			},
			"renewable": {
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "Flag to allow the token to be renewed",
			},
			"ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The TTL period of the token.",
			},
			"explicit_max_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The explicit max TTL of the token.",
			},
			"wrapping_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The TTL period of the wrapped token.",
			},
			"display_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Default:     "token",
				Description: "The display name of the token.",
			},
			"num_uses": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Computed:    true,
				Description: "The number of allowed uses of the token.",
			},
			"period": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				ForceNew:    true,
				Description: "The period of the token.",
			},
			"renew_min_lease": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "The minimum lease to renew token.",
			},
			"renew_increment": {
				Type:        schema.TypeInt,
				Required:    false,
				Optional:    true,
				Description: "The renew increment.",
			},
			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The token lease duration.",
			},
			"lease_started": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The token lease started on.",
			},
			"client_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client token.",
				Sensitive:   true,
			},
			"wrapped_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client wrapped token.",
				Sensitive:   true,
			},
			"wrapping_accessor": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client wrapping accessor.",
				Sensitive:   true,
			},
			"pgp_key": {
				Type:        schema.TypeString,
				ForceNew:    true,
				Optional:    true,
				Description: "The PGP key (base64 encoded) to encrypt the token.",
			},
			"encrypted_client_token": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The client token encrypted using the provided PGP key.",
				Sensitive:   true,
			},
		},
	}
}

func tokenCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	var err error
	var wrapped bool

	role := d.Get("role_name").(string)

	iPolicies := d.Get("policies").(*schema.Set).List()
	policies := make([]string, 0, len(iPolicies))
	for _, iPolicy := range iPolicies {
		policies = append(policies, iPolicy.(string))
	}

	var createRequest = &api.TokenCreateRequest{}

	if len(policies) > 0 {
		createRequest.Policies = policies
	}

	if v, ok := d.GetOk("ttl"); ok {
		createRequest.TTL = v.(string)
	}

	if v, ok := d.GetOk("explicit_max_ttl"); ok {
		createRequest.ExplicitMaxTTL = v.(string)
	}

	if v, ok := d.GetOk("period"); ok {
		createRequest.Period = v.(string)
	}

	if v, ok := d.GetOk("no_parent"); ok {
		createRequest.NoParent = v.(bool)
	}

	if v, ok := d.GetOk("no_default_policy"); ok {
		createRequest.NoDefaultPolicy = v.(bool)
	}

	if v, ok := d.GetOk("display_name"); ok {
		createRequest.DisplayName = v.(string)
	}

	if v, ok := d.GetOk("num_uses"); ok {
		createRequest.NumUses = v.(int)
	}

	if v, ok := d.GetOk("renewable"); ok {
		renewable := v.(bool)
		createRequest.Renewable = &renewable
	}

	if v, ok := d.GetOk("wrapping_ttl"); ok {
		wrappingTTL := v.(string)
		token := client.Token()

		client, err = client.Clone()
		if err != nil {
			return fmt.Errorf("error cloning client: %s", err)
		}
		client.SetToken(token)

		client.SetWrappingLookupFunc(func(operation, path string) string {
			return wrappingTTL
		})

		wrapped = true
	}

	var resp *api.Secret
	var accessor string

	if role != "" {
		log.Printf("[DEBUG] Creating token with role %q", role)
		resp, err = client.Auth().Token().CreateWithRole(createRequest, role)
		if err != nil {
			return fmt.Errorf("error creating token with role %q: %s", role, err)
		}

		if wrapped {
			accessor = resp.WrapInfo.WrappedAccessor
		} else {
			accessor = resp.Auth.Accessor
		}

		log.Printf("[DEBUG] Created token accessor %q with role %q", accessor, role)
	} else {
		log.Printf("[DEBUG] Creating token")
		resp, err = client.Auth().Token().Create(createRequest)
		if err != nil {
			return fmt.Errorf("error creating token: %s", err)
		}

		if wrapped {
			accessor = resp.WrapInfo.WrappedAccessor
		} else {
			accessor = resp.Auth.Accessor
		}

		log.Printf("[DEBUG] Created token accessor %q", accessor)
	}

	if wrapped {
		d.Set("wrapped_token", resp.WrapInfo.Token)
		d.Set("wrapping_accessor", resp.WrapInfo.Accessor)
	} else {
		if v, ok := d.GetOk("pgp_key"); ok {
			pgpKey := v.(string)
			encryptionKey, err := encryption.RetrieveGPGKey(pgpKey)
			if err != nil {
				return err
			}
			_, encrypted, err := encryption.EncryptValue(encryptionKey, resp.Auth.ClientToken, "Vault Token")
			if err != nil {
				return err
			}
			d.Set("client_token", "")
			d.Set("encrypted_client_token", encrypted)
		} else {
			d.Set("pgp_key", "")
			d.Set("client_token", resp.Auth.ClientToken)
			d.Set("encrypted_client_token", "")
		}
	}

	d.SetId(accessor)

	return tokenRead(d, meta)
}

func tokenRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	id := d.Get("client_token").(string)
	accessor := d.Id()

	log.Printf("[DEBUG] Reading token accessor %q", accessor)
	resp, err := client.Auth().Token().LookupAccessor(accessor)
	if err != nil {
		log.Printf("[WARN] Token not found, removing from state")
		d.SetId("")
		return nil
	}

	log.Printf("[DEBUG] Read token accessor %q", accessor)

	iPolicies := resp.Data["policies"].([]interface{})
	policies := make([]string, 0, len(iPolicies))
	for _, iPolicy := range iPolicies {
		if iPolicy == "default" {
			continue
		}

		policies = append(policies, iPolicy.(string))
	}

	d.Set("policies", policies)
	d.Set("no_parent", resp.Data["orphan"])

	// root tokens don't have the renewable key.
	renewable := resp.Data["renewable"].(*bool)
	if renewable != nil {
		d.Set("renewable", *renewable)
	} else {
		d.Set("renewable", false)
	}

	d.Set("display_name", strings.TrimPrefix(resp.Data["display_name"].(string), "token-"))
	d.Set("num_uses", resp.Data["num_uses"])
	if _, ok := d.GetOk("pgp_key"); !ok {
		d.Set("pgp_key", "")
	}
	if _, ok := d.GetOk("encrypted_client_token"); !ok {
		d.Set("encrypted_client_token", "")
	}

	issueTimeStr, ok := resp.Data["issue_time"].(string)
	if !ok {
		return fmt.Errorf("error issue_time is not a string, got %T", resp.Data["issue_time"])
	}

	issueTime, err := time.Parse(time.RFC3339Nano, issueTimeStr)
	if err != nil {
		return fmt.Errorf("error parsing issue_time: %s, please format string like '2006-01-02T15:04:05.999999999Z07:00'", err)
	}
	d.Set("lease_started", issueTime.Format(time.RFC3339))

	expireTimeStr, ok := resp.Data["expire_time"].(string)
	if !ok {
		// A root token have a nil expire_time as well, but renewable is missing.
		if renewable != nil {
			log.Printf("[WARN] Token is expired, revoking and removing from state")

			err := client.Auth().Token().RevokeAccessor(id)
			if err != nil {
				log.Printf("[WARN] Token %s could not be revoked. %s", id, err)
			}

			d.SetId("")
			return nil
		}

		d.Set("lease_duration", 0)
	} else {
		expireTime, err := time.Parse(time.RFC3339Nano, expireTimeStr)
		if err != nil {
			return fmt.Errorf("error parsing expire_time: %s", err)
		}

		d.Set("lease_duration", int(expireTime.Sub(issueTime).Seconds()))
	}

	if d.Get("renewable").(bool) && tokenCheckLease(d) {
		if id == "" {
			log.Printf("[DEBUG] Lease for token access %q cannot be renewed as it's been encrypted.", accessor)
			return nil
		}

		log.Printf("[DEBUG] Lease for token accessor %q expiring soon, renewing", accessor)

		increment := d.Get("lease_duration").(int)

		if v, ok := d.GetOk("renew_increment"); ok {
			increment = v.(int)
		}

		renewed, err := client.Auth().Token().Renew(id, increment)
		if err != nil {
			log.Printf("[DEBUG] Error renewing token, removing from state")
			d.SetId("")
			return nil
		}

		log.Printf("[DEBUG] Lease for token accessor %q renewed, new lease duration %d", id, renewed.Auth.LeaseDuration)

		d.Set("lease_duration", renewed.Data["lease_duration"])
		d.Set("lease_started", time.Now().Format(time.RFC3339))
		d.Set("client_token", renewed.Auth.ClientToken)

		d.SetId(renewed.Auth.Accessor)
	}

	return nil
}

func tokenUpdate(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func tokenDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	token := d.Id()

	log.Printf("[DEBUG] Deleting token %q", token)
	err := client.Auth().Token().RevokeAccessor(token)
	if err != nil {
		return fmt.Errorf("error deleting token %q: %s", token, err)
	}
	log.Printf("[DEBUG] Deleted token accessor %q", token)

	return nil
}

func tokenExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	accessor := d.Id()

	log.Printf("[DEBUG] Checking if token accessor %q exists", accessor)
	resp, err := client.Auth().Token().LookupAccessor(accessor)
	if err != nil {
		log.Printf("[DEBUG] token accessor %q not found: %s", d.Id(), err)
		return false, nil
	}
	return resp != nil, nil
}

func tokenCheckLease(d *schema.ResourceData) bool {
	accessor := d.Id()

	startedStr := d.Get("lease_started").(string)
	if startedStr == "" {
		return false
	}

	started, err := time.Parse(time.RFC3339, startedStr)
	if err != nil {
		log.Printf("[DEBUG] lease_started %q for token accessor %q is an invalid value, removing: %s", startedStr, accessor, err)
		d.SetId("")

		return false
	}

	leaseDuration := d.Get("lease_duration").(int)

	expireTime := started.Add(time.Second * time.Duration(leaseDuration))
	if expireTime.Before(time.Now()) {
		log.Printf("[DEBUG] token accessor %q has expired", accessor)
		d.SetId("")

		return false
	}

	if v, ok := d.GetOk("renew_min_lease"); ok {
		renewMinLease := v.(int)
		if renewMinLease <= 0 {
			return false
		}

		renewTime := int(expireTime.Sub(time.Now()).Seconds())
		if renewTime <= renewMinLease {
			log.Printf("[DEBUG] token accessor %q must be renewed", accessor)

			return true
		}
	}

	return false
}

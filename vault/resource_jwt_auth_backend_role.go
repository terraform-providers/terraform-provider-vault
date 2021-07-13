package vault

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

var (
	jwtAuthBackendRoleBackendFromPathRegex = regexp.MustCompile("^auth/(.+)/role/.+$")
	jwtAuthBackendRoleNameFromPathRegex    = regexp.MustCompile("^auth/.+/role/(.+)$")
)

func jwtAuthBackendRoleResource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"role_name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the role.",
			ForceNew:    true,
		},
		"role_type": {
			Type:        schema.TypeString,
			Description: "Type of role, either \"oidc\" (default) or \"jwt\"",
			Optional:    true,
			Computed:    true,
			ForceNew:    true,
		},
		"bound_audiences": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of aud claims to match against. Any match is sufficient.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"user_claim": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The claim to use to uniquely identify the user; this will be used as the name for the Identity entity alias created due to a successful login.",
		},
		"clock_skew_leeway": {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     0,
			Description: "The amount of leeway to add to all claims to account for clock skew, in seconds. Defaults to 60 seconds if set to 0 and can be disabled if set to -1. Only applicable with 'jwt' roles.",
		},
		"expiration_leeway": {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     0,
			Description: "The amount of leeway to add to expiration (exp) claims to account for clock skew, in seconds. Defaults to 60 seconds if set to 0 and can be disabled if set to -1. Only applicable with 'jwt' roles.",
		},
		"not_before_leeway": {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     0,
			Description: "The amount of leeway to add to not before (nbf) claims to account for clock skew, in seconds. Defaults to 150 seconds if set to 0 and can be disabled if set to -1. Only applicable with 'jwt' roles. ",
		},
		"allowed_redirect_uris": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Description: "The list of allowed values for redirect_uri during OIDC logins.",
		},
		"bound_subject": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "If set, requires that the sub claim matches this value.",
		},
		"oidc_scopes": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of OIDC scopes to be used with an OIDC role. The standard scope \"openid\" is automatically included and need not be specified.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"bound_claims_type": {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "How to interpret values in the claims/values map: can be either \"string\" (exact match) or \"glob\" (wildcard match).",
		},
		"bound_claims": {
			Type:        schema.TypeMap,
			Optional:    true,
			Description: "Map of claims/values to match against. The expected value may be a single string or a comma-separated string list.",
		},
		"claim_mappings": {
			Type:        schema.TypeMap,
			Optional:    true,
			Description: "Map of claims (keys) to be copied to specified metadata fields (values).",
		},
		"groups_claim": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "The claim to use to uniquely identify the set of groups to which the user belongs; this will be used as the names for the Identity group aliases created due to a successful login. The claim value must be a list of strings.",
		},
		"groups_claim_delimiter_pattern": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "A pattern of delimiters used to allow the groups_claim to live outside of the top-level JWT structure. For instance, a groups_claim of meta/user.name/groups with this field set to // will expect nested structures named meta, user.name, and groups. If this field was set to /./ the groups information would expect to be via nested structures of meta, user, name, and groups.",
			Deprecated:  "`groups_claim_delimiter_pattern` has been removed since Vault 1.1. If the groups claim is not at the top level, it can now be specified as a JSONPointer.",
		},
		"verbose_oidc_logging": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Log received OIDC tokens and claims when debug-level logging is active. Not recommended in production since sensitive information may be present in OIDC responses.",
		},
		"backend": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Unique name of the auth backend to configure.",
			ForceNew:    true,
			Default:     "jwt",
			// standardise on no beginning or trailing slashes
			StateFunc: func(v interface{}) string {
				return strings.Trim(v.(string), "/")
			},
		},

		// Deprecated
		"policies": {
			Type:     schema.TypeSet,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Description:   "Policies to be set on tokens issued using this role.",
			Deprecated:    "use `token_policies` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_policies"},
		},
		"ttl": {
			Type:          schema.TypeInt,
			Optional:      true,
			Description:   "Default number of seconds to set as the TTL for issued tokens and at renewal time.",
			ConflictsWith: []string{"period", "token_ttl", "token_period"},
			Deprecated:    "use `token_ttl` instead if you are running Vault >= 1.2",
		},
		"max_ttl": {
			Type:          schema.TypeInt,
			Optional:      true,
			Description:   "Number of seconds after which issued tokens can no longer be renewed.",
			Deprecated:    "use `token_max_ttl` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_max_ttl"},
		},
		"period": {
			Type:          schema.TypeInt,
			Optional:      true,
			Description:   "Number of seconds to set the TTL to for issued tokens upon renewal. Makes the token a periodic token, which will never expire as long as it is renewed before the TTL each period.",
			ConflictsWith: []string{"ttl", "token_period", "token_ttl"},
			Deprecated:    "use `token_period` instead if you are running Vault >= 1.2",
		},
		"num_uses": {
			Type:          schema.TypeInt,
			Optional:      true,
			Description:   "Number of times issued tokens can be used. Setting this to 0 or leaving it unset means unlimited uses.",
			Deprecated:    "use `token_num_uses` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_num_uses"},
		},
		"bound_cidrs": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of CIDRs valid as the source address for login requests. This value is also encoded into any resulting token.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Deprecated:    "use `token_bound_cidrs` instead if you are running Vault >= 1.2",
			ConflictsWith: []string{"token_bound_cidrs"},
		},
	}

	addTokenFields(fields, &addTokenFieldsConfig{
		TokenBoundCidrsConflict: []string{"bound_cidrs"},
		TokenMaxTTLConflict:     []string{"max_ttl"},
		TokenNumUsesConflict:    []string{"num_uses"},
		TokenPeriodConflict:     []string{"period", "ttl", "token_ttl"},
		TokenPoliciesConflict:   []string{"policies"},
		TokenTTLConflict:        []string{"ttl", "period", "token_period"},
	})

	return &schema.Resource{
		Create: jwtAuthBackendRoleCreate,
		Read:   jwtAuthBackendRoleRead,
		Update: jwtAuthBackendRoleUpdate,
		Delete: jwtAuthBackendRoleDelete,
		Exists: jwtAuthBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: fields,
	}
}

func jwtAuthBackendRoleCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	role := d.Get("role_name").(string)
	path := jwtAuthBackendRolePath(backend, role)

	log.Printf("[DEBUG] Writing JWT auth backend role %q", path)
	data := jwtAuthBackendRoleDataToWrite(d, true)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing JWT auth backend role %q: %s", path, err)
	}
	d.SetId(path)
	log.Printf("[DEBUG] Wrote JWT auth backend role %q", path)

	if v, ok := d.GetOk("role_id"); ok {
		log.Printf("[DEBUG] Writing JWT auth backend role %q RoleID", path)
		_, err := client.Logical().Write(path+"/role-id", map[string]interface{}{
			"role_id": v.(string),
		})
		if err != nil {
			return fmt.Errorf("error writing JWT auth backend role %q's RoleID: %s", path, err)
		}
		log.Printf("[DEBUG] Wrote JWT auth backend role %q RoleID", path)
	}

	return jwtAuthBackendRoleRead(d, meta)
}

func jwtAuthBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	backend, err := jwtAuthBackendRoleBackendFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for JWT auth backend role: %s", path, err)
	}

	role, err := jwtAuthBackendRoleNameFromPath(path)
	if err != nil {
		return fmt.Errorf("invalid path %q for JWT auth backend role: %s", path, err)
	}

	log.Printf("[DEBUG] Reading JWT auth backend role %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading JWT auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read JWT auth backend role %q", path)
	if resp == nil {
		log.Printf("[WARN] JWT auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	readTokenFields(d, resp)

	// Check if the user is using the deprecated `policies`
	if _, deprecated := d.GetOk("policies"); deprecated {
		// Then we see if `token_policies` was set and unset it
		// Vault will still return `policies`
		if _, ok := d.GetOk("token_policies"); ok {
			d.Set("token_policies", nil)
		}

		if v, ok := resp.Data["policies"]; ok {
			d.Set("policies", v)
		}
	}

	// Check if the user is using the deprecated `period`
	if _, deprecated := d.GetOk("period"); deprecated {
		// Then we see if `token_period` was set and unset it
		// Vault will still return `period`
		if _, ok := d.GetOk("token_period"); ok {
			d.Set("token_period", nil)
		}

		if v, ok := resp.Data["period"]; ok {
			d.Set("period", v)
		}
	}

	// Check if the user is using the deprecated `ttl`
	if _, deprecated := d.GetOk("ttl"); deprecated {
		// Then we see if `token_ttl` was set and unset it
		// Vault will still return `ttl`
		if _, ok := d.GetOk("token_ttl"); ok {
			d.Set("token_ttl", nil)
		}

		if v, ok := resp.Data["ttl"]; ok {
			d.Set("ttl", v)
		}

	}

	// Check if the user is using the deprecated `max_ttl`
	if _, deprecated := d.GetOk("max_ttl"); deprecated {
		// Then we see if `token_max_ttl` was set and unset it
		// Vault will still return `max_ttl`
		if _, ok := d.GetOk("token_max_ttl"); ok {
			d.Set("token_max_ttl", nil)
		}

		if v, ok := resp.Data["max_ttl"]; ok {
			d.Set("max_ttl", v)
		}
	}

	// Check if the user is using the deprecated `num_uses`
	if _, deprecated := d.GetOk("num_uses"); deprecated {
		// Then we see if `token_num_uses` was set and unset it
		// Vault will still return `num_uses`
		if _, ok := d.GetOk("token_num_uses"); ok {
			d.Set("token_num_uses", nil)
		}

		if v, ok := resp.Data["num_uses"]; ok {
			d.Set("num_uses", v)
		}
	}

	// Check if the user is using the deprecated `bound_cidrs`
	if _, deprecated := d.GetOk("bound_cidrs"); deprecated {
		// Then we see if `token_bound_cidrs` was set and unset it
		// Vault will still return `bound_cidrs`
		if _, ok := d.GetOk("token_bound_cidrs"); ok {
			d.Set("token_bound_cidrs", nil)
		}

		if v, ok := resp.Data["bound_cidrs"]; ok {
			d.Set("bound_cidrs", v)
		}
	}

	if resp.Data["bound_audiences"] != nil {
		boundAuds := util.JsonStringArrayToStringArray(resp.Data["bound_audiences"].([]interface{}))
		err = d.Set("bound_audiences", boundAuds)
		if err != nil {
			return fmt.Errorf("error setting bound_audiences in state: %s", err)
		}
	}

	d.Set("user_claim", resp.Data["user_claim"].(string))

	if resp.Data["allowed_redirect_uris"] != nil {
		allowedRedirectUris := util.JsonStringArrayToStringArray(resp.Data["allowed_redirect_uris"].([]interface{}))
		err = d.Set("allowed_redirect_uris", allowedRedirectUris)
		if err != nil {
			return fmt.Errorf("error setting allowed_redirect_uris in state: %s", err)
		}
	}

	d.Set("role_type", resp.Data["role_type"].(string))
	d.Set("bound_subject", resp.Data["bound_subject"].(string))

	if resp.Data["oidc_scopes"] != nil {
		cidrs := util.JsonStringArrayToStringArray(resp.Data["oidc_scopes"].([]interface{}))
		err = d.Set("oidc_scopes", cidrs)
		if err != nil {
			return fmt.Errorf("error setting oidc_scopes in state: %s", err)
		}
	} else {
		d.Set("oidc_scopes", make([]string, 0))
	}

	if v, ok := resp.Data["bound_claims_type"]; ok {
		d.Set("bound_claims_type", v)
	}

	if resp.Data["bound_claims"] != nil {
		boundClaims := make(map[string]interface{})
		respBoundClaims := resp.Data["bound_claims"].(map[string]interface{})
		for k, v := range respBoundClaims {
			switch boundClaimVal := v.(type) {
			case []interface{}:
				boundClaims[k] = strings.Join(util.JsonStringArrayToStringArray(boundClaimVal), ",")
			case string:
				boundClaims[k] = boundClaimVal
			default:
				return fmt.Errorf("bound claim is not a string or list: %v", v)
			}
		}
		d.Set("bound_claims", boundClaims)
	}

	if resp.Data["claim_mappings"] != nil {
		d.Set("claim_mappings", resp.Data["claim_mappings"])
	}

	d.Set("groups_claim", resp.Data["groups_claim"].(string))
	if resp.Data["groups_claim_delimiter_pattern"] != nil {
		d.Set("groups_claim_delimiter_pattern", resp.Data["groups_claim_delimiter_pattern"].(string))
	}

	if v, ok := resp.Data["clock_skew_leeway"]; ok {
		d.Set("clock_skew_leeway", v)
	}
	if v, ok := resp.Data["expiration_leeway"]; ok {
		d.Set("expiration_leeway", v)
	}
	if v, ok := resp.Data["not_before_leeway"]; ok {
		d.Set("not_before_leeway", v)
	}
	if v, ok := resp.Data["verbose_oidc_logging"]; ok {
		d.Set("verbose_oidc_logging", v)
	}

	d.Set("backend", backend)
	d.Set("role_name", role)

	return nil
}

func jwtAuthBackendRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Updating JWT auth backend role %q", path)
	data := jwtAuthBackendRoleDataToWrite(d, false)
	_, err := client.Logical().Write(path, data)

	d.SetId(path)

	if err != nil {
		return fmt.Errorf("error updating JWT auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated JWT auth backend role %q", path)

	if d.HasChange("role_id") {
		log.Printf("[DEBUG] Updating JWT auth backend role %q RoleID", path)
		_, err := client.Logical().Write(path+"/role-id", map[string]interface{}{
			"role_id": d.Get("role_id").(string),
		})
		if err != nil {
			return fmt.Errorf("error updating JWT auth backend role %q's RoleID: %s", path, err)
		}
		log.Printf("[DEBUG] Updated JWT auth backend role %q RoleID", path)
	}

	return jwtAuthBackendRoleRead(d, meta)

}

func jwtAuthBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting JWT auth backend role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil && !util.Is404(err) {
		return fmt.Errorf("error deleting JWT auth backend role %q", path)
	} else if err != nil {
		log.Printf("[DEBUG] JWT auth backend role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted JWT auth backend role %q", path)

	return nil
}

func jwtAuthBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if JWT auth backend role %q exists", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if JWT auth backend role %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if JWT auth backend role %q exists", path)

	return resp != nil, nil
}

func jwtAuthBackendRolePath(backend, role string) string {
	return "auth/" + strings.Trim(backend, "/") + "/role/" + strings.Trim(role, "/")
}

func jwtAuthBackendRoleNameFromPath(path string) (string, error) {
	if !jwtAuthBackendRoleNameFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no role found")
	}
	res := jwtAuthBackendRoleNameFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for role", len(res))
	}
	return res[1], nil
}

func jwtAuthBackendRoleBackendFromPath(path string) (string, error) {
	if !jwtAuthBackendRoleBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := jwtAuthBackendRoleBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}

func jwtAuthBackendRoleDataToWrite(d *schema.ResourceData, create bool) map[string]interface{} {
	data := map[string]interface{}{}

	updateTokenFields(d, data, create)

	data["bound_audiences"] = util.TerraformSetToStringArray(d.Get("bound_audiences"))
	data["user_claim"] = d.Get("user_claim").(string)

	if dataList := util.TerraformSetToStringArray(d.Get("allowed_redirect_uris")); len(dataList) > 0 {
		data["allowed_redirect_uris"] = dataList
	}

	if v, ok := d.GetOk("role_type"); ok {
		data["role_type"] = v.(string)
	}

	if v, ok := d.GetOkExists("bound_subject"); ok {
		data["bound_subject"] = v.(string)
	}

	if dataList := util.TerraformSetToStringArray(d.Get("oidc_scopes")); len(dataList) > 0 {
		data["oidc_scopes"] = dataList
	}

	if v, ok := d.GetOkExists("bound_claims_type"); ok {
		data["bound_claims_type"] = v.(string)
	}

	if v, ok := d.GetOk("bound_claims"); ok {
		boundClaims := make(map[string]interface{})
		for key, val := range v.(map[string]interface{}) {
			valStr := val.(string)
			if strings.Contains(valStr, ",") {
				vals := strings.Split(valStr, ",")
				for i := range vals {
					vals[i] = strings.TrimSpace(vals[i])
				}
				boundClaims[key] = vals
			} else {
				boundClaims[key] = valStr
			}
		}
		data["bound_claims"] = boundClaims
	}

	if v, ok := d.GetOk("claim_mappings"); ok {
		data["claim_mappings"] = v
	}

	if v, ok := d.GetOkExists("groups_claim"); ok {
		data["groups_claim"] = v.(string)
	}

	if v, ok := d.GetOkExists("groups_claim_delimiter_pattern"); ok {
		data["groups_claim_delimiter_pattern"] = v.(string)
	}

	data["clock_skew_leeway"] = d.Get("clock_skew_leeway").(int)
	data["expiration_leeway"] = d.Get("expiration_leeway").(int)
	data["not_before_leeway"] = d.Get("not_before_leeway").(int)

	data["verbose_oidc_logging"] = d.Get("verbose_oidc_logging").(bool)

	// Deprecated Fields
	if dataList := util.TerraformSetToStringArray(d.Get("policies")); len(dataList) > 0 {
		data["policies"] = dataList
	}
	if v, ok := d.GetOk("ttl"); ok {
		data["ttl"] = v.(int)
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		data["max_ttl"] = v.(int)
	}
	if v, ok := d.GetOk("period"); ok {
		data["period"] = v.(int)
	}
	if v, ok := d.GetOk("num_uses"); ok {
		data["num_uses"] = v.(int)
	}
	if dataList := util.TerraformSetToStringArray(d.Get("bound_cidrs")); len(dataList) > 0 {
		data["bound_cidrs"] = dataList
	}

	return data
}

package vault

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
)

func expandAuthMethodTune(rawL []interface{}) api.MountConfigInput {
	data := api.MountConfigInput{}
	if len(rawL) == 0 {
		return data
	}
	raw := rawL[0].(map[string]interface{})

	if v, ok := raw["default_lease_ttl"]; ok {
		data.DefaultLeaseTTL = v.(string)
	}
	if v, ok := raw["max_lease_ttl"]; ok {
		data.MaxLeaseTTL = v.(string)
	}
	if v, ok := raw["audit_non_hmac_request_keys"]; ok {
		data.AuditNonHMACRequestKeys = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := raw["audit_non_hmac_response_keys"]; ok {
		data.AuditNonHMACResponseKeys = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := raw["listing_visibility"]; ok {
		s := v.(string)
		if s == "" {
			s = "hidden"
		}

		data.ListingVisibility = s
	}
	if v, ok := raw["passthrough_request_headers"]; ok {
		data.PassthroughRequestHeaders = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := raw["allowed_response_headers"]; ok {
		data.AllowedResponseHeaders = expandStringSliceWithEmpty(v.([]interface{}), true)
	}
	if v, ok := raw["token_type"]; ok {
		data.TokenType = v.(string)
	}
	return data
}

func flattenAuthMethodTune(dt *api.MountConfigOutput) map[string]interface{} {
	m := make(map[string]interface{})

	m["default_lease_ttl"] = flattenVaultDuration(dt.DefaultLeaseTTL)
	m["max_lease_ttl"] = flattenVaultDuration(dt.MaxLeaseTTL)
	if len(dt.AuditNonHMACRequestKeys) > 0 && dt.AuditNonHMACRequestKeys[0] != "" {
		m["audit_non_hmac_request_keys"] = flattenStringSlice(dt.AuditNonHMACRequestKeys)
	}
	if len(dt.AuditNonHMACResponseKeys) > 0 && dt.AuditNonHMACResponseKeys[0] != "" {
		m["audit_non_hmac_response_keys"] = flattenStringSlice(dt.AuditNonHMACResponseKeys)
	}
	m["listing_visibility"] = dt.ListingVisibility
	if len(dt.PassthroughRequestHeaders) > 0 && dt.PassthroughRequestHeaders[0] != "" {
		m["passthrough_request_headers"] = flattenStringSlice(dt.PassthroughRequestHeaders)
	}
	if len(dt.AllowedResponseHeaders) > 0 && dt.AllowedResponseHeaders[0] != "" {
		m["allowed_response_headers"] = flattenStringSlice(dt.AllowedResponseHeaders)
	}
	m["token_type"] = dt.TokenType
	return m
}

func expandStringSlice(configured []interface{}) []string {
	vs := make([]string, 0, len(configured))
	for _, v := range configured {
		val, ok := v.(string)
		if ok && val != "" {
			vs = append(vs, v.(string))
		}
	}
	return vs
}

func expandStringSliceWithEmpty(configured []interface{}, returnSingleEmpty bool) []string {
	if returnSingleEmpty && len(configured) == 0 {
		return []string{""}
	}
	vs := make([]string, 0, len(configured))
	for _, v := range configured {
		val, ok := v.(string)
		if ok && val != "" {
			vs = append(vs, v.(string))
		}
	}
	return vs
}

func flattenStringSlice(list []string) []interface{} {
	vs := make([]interface{}, 0, len(list))
	for _, v := range list {
		vs = append(vs, v)
	}
	return vs
}

func flattenCommaSeparatedStringSlice(s string) []interface{} {
	split := strings.Split(s, ",")
	vs := make([]interface{}, 0, len(split))
	for _, v := range split {
		vs = append(vs, v)
	}
	log.Printf("[INFO] flattenedCommaSeparatedList: %+v", vs)
	return vs
}

func flattenVaultDuration(d interface{}) string {
	if d == nil {
		return time.Duration(0).String()
	}

	switch d.(type) {
	case int:
		return util.ShortDur(time.Duration(d.(int)) * time.Second)
	case int64:
		return util.ShortDur(time.Duration(d.(int64)) * time.Second)
	case json.Number:
		if i, err := d.(json.Number).Int64(); err == nil {
			return util.ShortDur(time.Duration(i) * time.Second)
		}
	}

	return time.Duration(0).String()
}

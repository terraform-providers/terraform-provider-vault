package vault

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

type GCPBinding struct {
	Resource string
	Roles    []string
}

func gcpSecretFlattenBinding(v interface{}) interface{} {
	transformed := schema.NewSet(gcpSecretBindingHash, []interface{}{})
	if v == nil {
		return transformed
	}

	rawBindings := v.((map[string]interface{}))
	for resource, roles := range rawBindings {
		transformed.Add(map[string]interface{}{
			"resource": resource,
			"roles":    schema.NewSet(schema.HashString, roles.([]interface{})),
		})
	}

	return transformed
}

func gcpSecretBindingHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["resource"].(string)))

	// We need to make sure to sort the strings below so that we always
	// generate the same hash code no matter what is in the set.
	if v, ok := m["roles"]; ok {
		vs := v.(*schema.Set).List()
		s := make([]string, len(vs))
		for i, raw := range vs {
			s[i] = raw.(string)
		}
		sort.Strings(s)

		for _, v := range s {
			buf.WriteString(fmt.Sprintf("%s-", v))
		}
	}
	return hashcode.String(buf.String())
}

func gcpSecretRenderBinding(binding *GCPBinding) string {
	output := fmt.Sprintf("resource \"%s\" {\n", binding.Resource)
	output = fmt.Sprintf("%s  roles = %s\n", output, policyRenderListOfStrings(binding.Roles))
	return fmt.Sprintf("%s}\n", output)
}

func gcpSecretRenderBindings(bindings []*GCPBinding) string {
	var output string

	for i, binding := range bindings {
		if i == 0 {
			output = fmt.Sprintf("%s", gcpSecretRenderBinding(binding))
		} else {
			output = fmt.Sprintf("%s\n\n%s", output, gcpSecretRenderBinding(binding))
		}
	}

	return output
}

func gcpSecretRenderBindingsFromData(v interface{}) string {
	rawBindings := v.(*schema.Set).List()

	bindings := make([]*GCPBinding, len(rawBindings))

	for i, binding := range rawBindings {
		rawRoles := binding.(map[string]interface{})["roles"].(*schema.Set).List()
		roles := make([]string, len(rawRoles))
		for j, role := range rawRoles {
			roles[j] = role.(string)
		}

		binding := &GCPBinding{
			Resource: binding.(map[string]interface{})["resource"].(string),
			Roles:    roles,
		}
		bindings[i] = binding
	}

	return gcpSecretRenderBindings(bindings)
}

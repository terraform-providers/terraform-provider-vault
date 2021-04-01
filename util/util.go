package util

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func JsonDiffSuppress(k, old, new string, d *schema.ResourceData) bool {
	var oldJSON, newJSON interface{}
	err := json.Unmarshal([]byte(old), &oldJSON)
	if err != nil {
		log.Printf("[ERROR] Version of %q in state is not valid JSON: %s", k, err)
		return false
	}
	err = json.Unmarshal([]byte(new), &newJSON)
	if err != nil {
		log.Printf("[ERROR] Version of %q in config is not valid JSON: %s", k, err)
		return false
	}
	return reflect.DeepEqual(oldJSON, newJSON)
}

func ToStringArray(input []interface{}) []string {
	output := make([]string, len(input))

	for i, item := range input {
		output[i] = item.(string)
	}

	return output
}

func Is404(err error) bool {
	return strings.Contains(err.Error(), "Code: 404")
}

func CalculateConflictsWith(self string, group []string) []string {
	if len(group) < 2 {
		return []string{}
	}
	results := make([]string, 0, len(group)-2)
	for _, item := range group {
		if item == self {
			continue
		}
		results = append(results, item)
	}
	return results
}

func ArrayToTerraformList(values []string) string {
	output := make([]string, len(values))
	for idx, value := range values {
		output[idx] = fmt.Sprintf(`"%s"`, value)
	}
	return fmt.Sprintf("[%s]", strings.Join(output, ", "))
}

func TerraformSetToStringArray(set interface{}) []string {
	list := set.(*schema.Set).List()
	arr := make([]string, 0, len(list))
	for _, v := range list {
		arr = append(arr, v.(string))
	}
	return arr
}

func JsonStringArrayToStringArray(jsonList []interface{}) []string {
	strList := make([]string, 0, len(jsonList))
	for _, v := range jsonList {
		strList = append(strList, v.(string))
	}
	return strList
}

func IsExpiredTokenErr(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "invalid accessor") {
		return true
	}
	if strings.Contains(err.Error(), "failed to find accessor entry") {
		return true
	}
	return false
}

func TestAccPreCheck(t *testing.T) {
	if v := os.Getenv("VAULT_ADDR"); v == "" {
		t.Fatal("VAULT_ADDR must be set for acceptance tests")
	}
	if v := os.Getenv("VAULT_TOKEN"); v == "" {
		t.Fatal("VAULT_TOKEN must be set for acceptance tests")
	}
}

func TestEntPreCheck(t *testing.T) {
	isEnterprise := os.Getenv("TF_ACC_ENTERPRISE")
	if isEnterprise == "" {
		t.Skip("TF_ACC_ENTERPRISE is not set, test is applicable only for Enterprise version of Vault")
	}
	if v := os.Getenv("VAULT_ADDR"); v == "" {
		t.Fatal("VAULT_ADDR must be set for acceptance tests")
	}
	if v := os.Getenv("VAULT_TOKEN"); v == "" {
		t.Fatal("VAULT_TOKEN must be set for acceptance tests")
	}
}

func GetTestADCreds(t *testing.T) (string, string, string) {
	adBindDN := os.Getenv("AD_BINDDN")
	adBindPass := os.Getenv("AD_BINDPASS")
	adURL := os.Getenv("AD_URL")

	if adBindDN == "" {
		t.Skip("AD_BINDDN not set")
	}
	if adBindPass == "" {
		t.Skip("AD_BINDPASS not set")
	}
	if adURL == "" {
		t.Skip("AD_URL not set")
	}
	return adBindDN, adBindPass, adURL
}

func GetTestNomadCreds(t *testing.T) (string, string) {
	address := os.Getenv("NOMAD_ADDR")
	token := os.Getenv("NOMAD_TOKEN")

	if address == "" {
		t.Skip("NOMAD_ADDR not set")
	}
	if token == "" {
		t.Skip("NOMAD_TOKEN not set")
	}

	return address, token
}

func TestCheckResourceAttrJSON(name, key, expectedValue string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("not found: %q", name)
		}
		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("%q has no primary instance state", name)
		}
		v, ok := instanceState.Attributes[key]
		if !ok {
			return fmt.Errorf("%s: attribute not found %q", name, key)
		}
		if expectedValue == "" && v == expectedValue {
			return nil
		}
		if v == "" {
			return fmt.Errorf("%s: attribute %q expected %#v, got %#v", name, key, expectedValue, v)
		}

		var stateJSON, expectedJSON interface{}
		err := json.Unmarshal([]byte(v), &stateJSON)
		if err != nil {
			return fmt.Errorf("%s: attribute %q not JSON: %s", name, key, err)
		}
		err = json.Unmarshal([]byte(expectedValue), &expectedJSON)
		if err != nil {
			return fmt.Errorf("expected value %q not JSON: %s", expectedValue, err)
		}
		if !reflect.DeepEqual(stateJSON, expectedJSON) {
			return fmt.Errorf("%s: attribute %q expected %#v, got %#v", name, key, expectedJSON, stateJSON)
		}
		return nil
	}
}

func ShortDur(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func SliceHasElement(list []interface{}, search interface{}) (bool, int) {
	for i, ele := range list {
		if reflect.DeepEqual(ele, search) {
			return true, i
		}
	}
	return false, -1
}

func SliceAppendIfMissing(list []interface{}, search interface{}) []interface{} {
	if found, _ := SliceHasElement(list, search); !found {
		return append(list, search)
	}

	return list
}

// Warning: Slice order will be modified
func SliceRemoveIfPresent(list []interface{}, search interface{}) []interface{} {
	if found, index := SliceHasElement(list, search); found {
		// Set the index we found to be the last item
		list[index] = list[len(list)-1]
		// Return slice sans last item
		return list[:len(list)-1]
	}

	return list
}

// Example data:
//   - userSuppliedPath = "transform"
//   - endpoint = "/transform/role/{name}"
//   - parameters will include path parameters
func ParsePath(userSuppliedPath, endpoint string, d *schema.ResourceData) string {
	fields := strings.Split(endpoint, "/")
	if fields[0] == "" {
		// There was a leading slash that should be trimmed.
		fields = fields[1:]
	}
	isAuthPath := false
	if fields[0] == "auth" {
		fields = fields[1:]
		isAuthPath = true
	}

	// The first field should be the one the user supplied rather
	// than the default one shown.
	fields[0] = userSuppliedPath

	// Since endpoints start with a "/", the first field is always
	// an extraneous "" and should be dropped.
	recomprised := "/" + strings.Join(fields, "/")
	if isAuthPath {
		recomprised = "/auth" + recomprised
	}

	// For a recomprised string like "/my-transform/role/{name}",
	// this will return the fields of "/transform/role/" and
	// "name".
	fields = strings.FieldsFunc(recomprised, func(c rune) bool {
		return c == '{' || c == '}'
	})
	for _, field := range fields {
		valRaw, ok := d.GetOk(field)
		if !ok {
			continue
		}
		// All path parameters must be strings so it's safe to
		// assume here.
		val := valRaw.(string)
		recomprised = strings.Replace(recomprised, fmt.Sprintf("{%s}", field), val, -1)
	}
	return recomprised
}

// PathParameters is just like regexp FindStringSubmatch,
// but it validates that the match is different from the string passed
// in, and that there's only one result.
func PathParameters(endpoint, vaultPath string) (map[string]string, error) {
	fields := strings.Split(endpoint, "/")

	// The first field is always "", let's strip it.
	if fields[0] != "" {
		return nil, fmt.Errorf("expected an endpoint starting with / but received %q", endpoint)
	}
	fields = fields[1:]

	// For paths beginning with auth, if we strip it off we can
	// parse them like the rest.
	isAuthEndpoint := false
	if fields[0] == "auth" {
		if len(fields) < 2 {
			// There are no further path parameters to parse.
			return nil, nil
		}
		fields = fields[1:]
		isAuthEndpoint = true
	}
	fields[0] = "{path}"

	for i, field := range fields {
		if strings.HasPrefix(field, "{") {
			fields[i] = strings.ReplaceAll(fields[i], "{", "(?P<")
			fields[i] = strings.ReplaceAll(fields[i], "}", ">.+)")
		}
	}
	pattern := "/"
	if isAuthEndpoint {
		pattern += "auth/"
	}
	pattern += strings.Join(fields, "/")

	endpointReg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("unable to compile regex: %q: %w\n", pattern, err)
	}

	match := endpointReg.FindStringSubmatch(vaultPath)
	result := make(map[string]string)
	for i, fieldName := range endpointReg.SubexpNames() {
		if i == 0 || fieldName == "" {
			continue
		}
		if i >= len(match) {
			return nil, fmt.Errorf("could not parse %q into %q", vaultPath, endpoint)
		}
		result[fieldName] = match[i]
	}
	return result, nil
}

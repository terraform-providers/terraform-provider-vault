package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
	"golang.org/x/oauth2/google"
)

// This test requires that you pass credentials for a user or service account having the IAM rights
// listed at https://www.vaultproject.io/docs/secrets/gcp/index.html for the project you are testing
// on. The credentials must also allow setting IAM permissions on the project being tested.
func TestGCPSecretStaticAccount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-gcp")
	staticAccount := acctest.RandomWithPrefix("tf-test")
	credentials, project := getTestGCPCreds(t)

	// We will use the provided key as the static account
	conf, err := google.JWTConfigFromJSON([]byte(credentials), "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		t.Fatalf("error decoding GCP Credentials: %v", err)
	}
	serviceAccountEmail := conf.Email

	noBindings := testGCPSecretStaticAccount_accessToken(backend, staticAccount, credentials, serviceAccountEmail, project)

	initialRole := "roles/viewer"
	initialConfig, initialHash := testGCPSecretStaticAccount_accessTokenBinding(backend, staticAccount, credentials, serviceAccountEmail, project, initialRole)

	updatedRole := "roles/browser"
	updatedConfig, updatedHash := testGCPSecretStaticAccount_accessTokenBinding(backend, staticAccount, credentials, serviceAccountEmail, project, updatedRole)

	keyConfig, keyHash := testGCPSecretStaticAccount_serviceAccountKey(backend, staticAccount, credentials, serviceAccountEmail, project, updatedRole)

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testGCPSecretStaticAccountDestroy,
		Steps: []resource.TestStep{
			{
				Config: noBindings,
				Check: resource.ComposeTestCheckFunc(
					testGCPSecretStaticAccount_attrs(backend, staticAccount),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "path", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "static_account", staticAccount),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "secret_type", "access_token"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "service_account_email", serviceAccountEmail),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "service_account_project", project),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "token_scopes.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "token_scopes.2400041053", "https://www.googleapis.com/auth/cloud-platform"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "binding.#", "0"),
				),
			},
			{
				Config: initialConfig,
				Check: resource.ComposeTestCheckFunc(
					testGCPSecretStaticAccount_attrs(backend, staticAccount),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "path", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "static_account", staticAccount),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "secret_type", "access_token"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "service_account_email", serviceAccountEmail),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "service_account_project", project),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "token_scopes.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "token_scopes.2400041053", "https://www.googleapis.com/auth/cloud-platform"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "binding.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", fmt.Sprintf("binding.%d.resource", initialHash), fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", fmt.Sprintf("binding.%d.roles.#", initialHash), "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", fmt.Sprintf("binding.%d.roles.3993311253", initialHash), initialRole),
				),
			},
			{
				ResourceName:            "vault_gcp_secret_static_account.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{},
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					testGCPSecretStaticAccount_attrs(backend, staticAccount),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "path", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "static_account", staticAccount),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "secret_type", "access_token"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "service_account_email", serviceAccountEmail),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "service_account_project", project),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "token_scopes.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "token_scopes.2400041053", "https://www.googleapis.com/auth/cloud-platform"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "binding.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", fmt.Sprintf("binding.%d.resource", updatedHash), fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", fmt.Sprintf("binding.%d.roles.#", updatedHash), "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", fmt.Sprintf("binding.%d.roles.2133424675", updatedHash), updatedRole),
				),
			},
			{
				Config: keyConfig,
				Check: resource.ComposeTestCheckFunc(
					testGCPSecretStaticAccount_attrs(backend, staticAccount),
					resource.TestCheckResourceAttr("vault_gcp_secret_backend.test", "path", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "static_account", staticAccount),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "secret_type", "service_account_key"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "service_account_email", serviceAccountEmail),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "service_account_project", project),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", "binding.#", "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", fmt.Sprintf("binding.%d.resource", keyHash), fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", fmt.Sprintf("binding.%d.roles.#", keyHash), "1"),
					resource.TestCheckResourceAttr("vault_gcp_secret_static_account.test", fmt.Sprintf("binding.%d.roles.2133424675", keyHash), updatedRole),
				),
			},
		},
	})
}

func testGCPSecretStaticAccount_attrs(backend, staticAccount string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_gcp_secret_static_account.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		endpoint := instanceState.ID

		if endpoint != backend+"/static-account/"+staticAccount {
			return fmt.Errorf("expected ID to be %q, got %q instead", backend+"/static-account/"+staticAccount, endpoint)
		}

		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read(endpoint)
		if err != nil {
			return fmt.Errorf("%q doesn't exist", endpoint)
		}

		attrs := map[string]string{
			"secret_type":             "secret_type",
			"service_account_project": "service_account_project",
			"token_scopes":            "token_scopes",
			"service_account_email":   "service_account_email",
		}
		for stateAttr, apiAttr := range attrs {
			if resp.Data[apiAttr] == nil && instanceState.Attributes[stateAttr] == "" {
				continue
			}
			var match bool
			switch resp.Data[apiAttr].(type) {
			case json.Number:
				apiData, err := resp.Data[apiAttr].(json.Number).Int64()
				if err != nil {
					return fmt.Errorf("expected API field %s to be an int, was %q", apiAttr, resp.Data[apiAttr])
				}
				stateData, err := strconv.ParseInt(instanceState.Attributes[stateAttr], 10, 64)
				if err != nil {
					return fmt.Errorf("expected state field %s to be an int, was %q", stateAttr, instanceState.Attributes[stateAttr])
				}
				match = apiData == stateData
			case bool:
				if _, ok := resp.Data[apiAttr]; !ok && instanceState.Attributes[stateAttr] == "" {
					match = true
				} else {
					stateData, err := strconv.ParseBool(instanceState.Attributes[stateAttr])
					if err != nil {
						return fmt.Errorf("expected state field %s to be a bool, was %q", stateAttr, instanceState.Attributes[stateAttr])
					}
					match = resp.Data[apiAttr] == stateData
				}
			case []interface{}:
				apiData := resp.Data[apiAttr].([]interface{})
				length := instanceState.Attributes[stateAttr+".#"]
				if length == "" {
					if len(resp.Data[apiAttr].([]interface{})) != 0 {
						return fmt.Errorf("expected state field %s to have %d entries, had 0", stateAttr, len(apiData))
					}
					match = true
				} else {
					count, err := strconv.Atoi(length)
					if err != nil {
						return fmt.Errorf("expected %s.# to be a number, got %q", stateAttr, instanceState.Attributes[stateAttr+".#"])
					}
					if count != len(apiData) {
						return fmt.Errorf("expected %s to have %d entries in state, has %d", stateAttr, len(apiData), count)
					}

					for i := 0; i < count; i++ {
						found := false
						for stateKey, stateValue := range instanceState.Attributes {
							if strings.HasPrefix(stateKey, stateAttr) {
								if apiData[i] == stateValue {
									found = true
								}
							}
						}
						if !found {
							return fmt.Errorf("Expected item %d of %s (%s in state) of %q to be in state but wasn't", i, apiAttr, stateAttr, apiData[i])
						}
					}
					match = true
				}
			default:
				match = resp.Data[apiAttr] == instanceState.Attributes[stateAttr]
			}
			if !match {
				return fmt.Errorf("expected %s (%s in state) of %q to be %q, got %q", apiAttr, stateAttr, endpoint, instanceState.Attributes[stateAttr], resp.Data[apiAttr])
			}
		}

		roleHashFunction := schema.HashSchema(&schema.Schema{
			Type: schema.TypeString,
		})

		// Bindings need to be tested separately
		remoteBindings := resp.Data["bindings"] // map[string]interface {}
		localBindingsLengthRaw := instanceState.Attributes["binding.#"]
		if localBindingsLengthRaw == "" {
			return fmt.Errorf("cannot find bindings from state")
		}
		localBindingsLength, err := strconv.Atoi(localBindingsLengthRaw)
		if err != nil {
			return fmt.Errorf("expected binding.# to be a number, got %q", localBindingsLengthRaw)
		}

		var remoteLength int
		if remoteBindings == nil {
			remoteLength = 0
		} else {
			remoteLength = len(remoteBindings.(map[string]interface{}))
		}
		if localBindingsLength != remoteLength {
			return fmt.Errorf("expected %s to have %d entries in state, has %d", "binding", remoteLength, localBindingsLength)
		}

		flattenedBindings := gcpSecretFlattenBinding(remoteBindings).(*schema.Set)
		for _, remoteBinding := range flattenedBindings.List() {
			bindingHash := strconv.Itoa(gcpSecretBindingHash(remoteBinding))

			remoteResource := remoteBinding.(map[string]interface{})["resource"].(string)
			localResource := instanceState.Attributes["binding."+bindingHash+".resource"]
			if localResource == "" {
				return fmt.Errorf("expected to find binding for resource %s in state, but didn't", remoteResource)
			}
			if localResource != remoteResource {
				return fmt.Errorf("expected to find binding for resource %s in state, but found %s instead", remoteResource, localResource)
			}

			// Check Roles
			remoteRoles := remoteBinding.(map[string]interface{})["roles"].(*schema.Set)
			localRolesCountRaw := instanceState.Attributes["binding."+bindingHash+".roles.#"]
			if localRolesCountRaw == "" {
				return fmt.Errorf("cannot find role counts for the binding for resource %s", remoteResource)
			}
			localRolesCount, err := strconv.Atoi(localRolesCountRaw)
			if err != nil {
				return fmt.Errorf("expected binding.%s.roles.# to be a number, got %q", remoteResource, localRolesCountRaw)
			}
			if remoteRoles.Len() != localRolesCount {
				return fmt.Errorf("expected %d roles for binding for resource %s but got %d instead", remoteRoles.Len(), remoteResource, localRolesCount)
			}

			for _, remoteRole := range remoteRoles.List() {
				roleHash := strconv.Itoa(roleHashFunction(remoteRole.(string)))
				log.Printf("[DEBUG] Path to look for %s for %s", "binding."+bindingHash+".roles."+roleHash, remoteRole.(string))
				localRole := instanceState.Attributes["binding."+bindingHash+".roles."+roleHash]
				if localRole == "" {
					return fmt.Errorf("expected to find role %s for binding for resource %s in state, but didn't", remoteRole.(string), remoteResource)
				}

				if localRole != remoteRole.(string) {
					return fmt.Errorf("expected to find role %s for binding for resource %s in state, but found %s instead", remoteRole.(string), remoteResource, localRole)
				}
			}
		}
		return nil
	}
}

func testGCPSecretStaticAccountDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_gcp_secret_static_account" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("error checking for GCP Secrets StaticAccount %q: %s", rs.Primary.ID, err)
		}
		if secret != nil {
			return fmt.Errorf("GCP Secrets StaticAccount %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testGCPSecretStaticAccount_accessToken(backend, staticAccount, credentials, serviceAccountEmail, project string) string {
	return fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_static_account" "test" {
  backend 			 = "${vault_gcp_secret_backend.test.path}"
	static_account = "%s"
  secret_type 	 = "access_token"
  token_scopes   = ["https://www.googleapis.com/auth/cloud-platform"]

	service_account_email = "%s"
}
`, backend, credentials, staticAccount, serviceAccountEmail)
}

func testGCPSecretStaticAccount_accessTokenBinding(backend, staticAccount, credentials, serviceAccountEmail, project, role string) (string, int) {
	resource := fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)

	terraform := fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_static_account" "test" {
  backend 			 = "${vault_gcp_secret_backend.test.path}"
	static_account = "%s"
  secret_type 	 = "access_token"
  token_scopes   = ["https://www.googleapis.com/auth/cloud-platform"]

	service_account_email = "%s"

  binding {
    resource = "%s"
    roles = ["%s"]
  }
}
`, backend, credentials, staticAccount, serviceAccountEmail, resource, role)

	// Hash the set of bindings
	binding := make(map[string]interface{})
	roles := []interface{}{role}
	binding["resource"] = resource
	binding["roles"] = schema.NewSet(schema.HashString, roles)

	return terraform, gcpSecretBindingHash(binding)
}

func testGCPSecretStaticAccount_serviceAccountKey(backend, staticAccount, credentials, serviceAccountEmail, project, role string) (string, int) {
	resource := fmt.Sprintf("//cloudresourcemanager.googleapis.com/projects/%s", project)

	terraform := fmt.Sprintf(`
resource "vault_gcp_secret_backend" "test" {
  path = "%s"
  credentials = <<CREDS
%s
CREDS
}

resource "vault_gcp_secret_static_account" "test" {
  backend 			 = "${vault_gcp_secret_backend.test.path}"
	static_account = "%s"
  secret_type 	 = "service_account_key"
  token_scopes   = ["https://www.googleapis.com/auth/cloud-platform"]

	service_account_email = "%s"

  binding {
    resource = "%s"
    roles = ["%s"]
  }
}
`, backend, credentials, staticAccount, serviceAccountEmail, resource, role)

	// Hash the set of bindings
	binding := make(map[string]interface{})
	roles := []interface{}{role}
	binding["resource"] = resource
	binding["roles"] = schema.NewSet(schema.HashString, roles)

	return terraform, gcpSecretBindingHash(binding)
}

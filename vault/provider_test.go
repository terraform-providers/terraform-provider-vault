package vault

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/pathorcontents"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/command/config"
	"github.com/mitchellh/go-homedir"
)

// How to run the acceptance tests for this provider:
//
// - Obtain an official Vault release from the Vault website at
//   https://vaultproject.io/ and extract the "vault" binary
//   somewhere.
//
// - Run the following to start the Vault server in development mode:
//       vault server -dev -dev-root-token-id=test
//
// - Take the "Root Token" value printed by Vault as the server started
//   up and set it as the value of the VAULT_TOKEN environment variable
//   in a new shell whose current working directory is the root of the
//   Terraform repository.
//
// - As directed by the Vault server output, set the VAULT_ADDR environment
//   variable. e.g.:
//       export VAULT_ADDR='http://127.0.0.1:8200'
//       export VAULT_TOKEN=test
//
// - Run the Terraform acceptance tests as usual:
//       make testacc TEST=./vault
//
// The tests expect to be run in a fresh, empty Vault and thus do not attempt
// to randomize or otherwise make the generated resource paths unique on
// each run. In case of weird behavior, restart the Vault dev server to
// start over with a fresh Vault. (Remember to reset VAULT_TOKEN.)

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

var testProvider *schema.Provider
var testProviders map[string]terraform.ResourceProvider

func init() {
	testProvider = Provider()
	testProviders = map[string]terraform.ResourceProvider{
		"vault": testProvider,
	}
}

func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("VAULT_ADDR"); v == "" {
		t.Fatal("VAULT_ADDR must be set for acceptance tests")
	}
	if v := os.Getenv("VAULT_TOKEN"); v == "" {
		t.Fatal("VAULT_TOKEN must be set for acceptance tests")
	}
}

func getTestAWSCreds(t *testing.T) (string, string) {
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if accessKey == "" {
		t.Skip("AWS_ACCESS_KEY_ID not set")
	}
	if secretKey == "" {
		t.Skip("AWS_SECRET_ACCESS_KEY not set")
	}
	return accessKey, secretKey
}

func getTestAWSRegion(t *testing.T) string {
	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		t.Skip("AWS_DEFAULT_REGION not set")
	}
	return region
}

type azureTestConf struct {
	SubscriptionID, TenantID, ClientID, ClientSecret, Scope string
}

func getTestAzureConf(t *testing.T) *azureTestConf {
	conf := &azureTestConf{
		SubscriptionID: os.Getenv("AZURE_SUBSCRIPTION_ID"),
		TenantID:       os.Getenv("AZURE_TENANT_ID"),
		ClientID:       os.Getenv("AZURE_CLIENT_ID"),
		ClientSecret:   os.Getenv("AZURE_CLIENT_SECRET"),
		Scope:          os.Getenv("AZURE_ROLE_SCOPE"),
	}
	if conf.SubscriptionID == "" {
		t.Skip("AZURE_SUBSCRIPTION_ID not set")
	}
	if conf.TenantID == "" {
		t.Skip("AZURE_TENANT_ID not set")
	}
	if conf.ClientID == "" {
		t.Skip("AZURE_CLIENT_ID not set")
	}
	if conf.ClientSecret == "" {
		t.Skip("AZURE_CLIENT_SECRET not set")
	}
	if conf.Scope == "" {
		t.Skip("AZURE_ROLE_SCOPE not set")
	}
	return conf
}

func getTestGCPCreds(t *testing.T) (string, string) {
	credentials := os.Getenv("GOOGLE_CREDENTIALS")
	project := os.Getenv("GOOGLE_PROJECT")

	if credentials == "" {
		t.Skip("GOOGLE_CREDENTIALS not set")
	}

	if project == "" {
		t.Skip("GOOGLE_PROJECT not set")
	}

	contents, _, err := pathorcontents.Read(credentials)
	if err != nil {
		t.Fatal("Error reading GOOGLE_CREDENTIALS: " + err.Error())
	}

	return string(contents), project
}

func getTestRMQCreds(t *testing.T) (string, string, string) {
	connectionUri := os.Getenv("RMQ_CONNECTION_URI")
	username := os.Getenv("RMQ_USERNAME")
	password := os.Getenv("RMQ_PASSWORD")
	if connectionUri == "" {
		t.Skip("RMQ_CONNECTION_URI not set")
	}
	if username == "" {
		t.Skip("RMQ_USERNAME not set")
	}
	if password == "" {
		t.Skip("RMQ_PASSWORD not set")
	}
	return connectionUri, username, password
}

// A basic token helper script.
const tokenHelperScript = `#!/usr/bin/env bash
echo "helper-token"
`

func TestAccAuthLoginProviderConfigure(t *testing.T) {
	rootProvider := Provider()
	rootProviderResource := &schema.Resource{
		Schema: rootProvider.Schema,
	}
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		Providers: map[string]terraform.ResourceProvider{
			"vault": rootProvider,
		},
		Steps: []resource.TestStep{
			{
				Config: testResourceApproleConfig_basic(),
				Check:  testResourceApproleLoginCheckAttrs(t),
			},
		},
	})

	rootProviderData := rootProviderResource.TestResourceData()
	if _, err := providerConfigure(rootProviderData); err != nil {
		t.Fatal(err)
	}
}

func TestTokenReadProviderConfigureWithHeaders(t *testing.T) {
	rootProvider := Provider()

	rootProviderResource := &schema.Resource{
		Schema: rootProvider.Schema,
	}
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testHeaderConfig("auth", "123"),
				Check:  testTokenName_check("token-testtoken"),
			},
		},
	})

	rootProviderData := rootProviderResource.TestResourceData()
	if _, err := providerConfigure(rootProviderData); err != nil {
		t.Fatal(err)
	}
}

func TestAccNamespaceProviderConfigure(t *testing.T) {
	isEnterprise := os.Getenv("TF_ACC_ENTERPRISE")
	if isEnterprise == "" {
		t.Skip("TF_ACC_ENTERPRISE is not set, test is applicable only for Enterprise version of Vault")
	}

	rootProvider := Provider()
	rootProviderResource := &schema.Resource{
		Schema: rootProvider.Schema,
	}
	rootProviderData := rootProviderResource.TestResourceData()
	if _, err := providerConfigure(rootProviderData); err != nil {
		t.Fatal(err)
	}

	namespacePath := acctest.RandomWithPrefix("test-namespace")

	//Create a test namespace and make sure it stays there
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		Providers: map[string]terraform.ResourceProvider{
			"vault": rootProvider,
		},
		Steps: []resource.TestStep{
			{
				Config: testNamespaceConfig(namespacePath),
				Check:  testNamespaceCheckAttrs(),
			},
		},
	})

	nsProvider := Provider()
	nsProviderResource := &schema.Resource{
		Schema: nsProvider.Schema,
	}
	nsProviderData := nsProviderResource.TestResourceData()
	nsProviderData.Set("namespace", namespacePath)
	nsProviderData.Set("token", os.Getenv("VAULT_TOKEN"))
	if _, err := providerConfigure(nsProviderData); err != nil {
		t.Fatal(err)
	}

	// Create a policy with sudo permissions and an orphaned periodic token within the test namespace
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		Providers: map[string]terraform.ResourceProvider{
			"vault": nsProvider,
		},
		Steps: []resource.TestStep{
			{
				Config: testResourceAdminPeriodicOrphanTokenConfig_basic(),
				Check:  testResourceAdminPeriodicOrphanTokenCheckAttrs(namespacePath, t),
			},
		},
	})

}

func testResourceApproleConfig_basic() string {
	return `
resource "vault_auth_backend" "approle" {
	type = "approle"
	path = "approle"
}

resource "vault_policy" "admin" {
    name = "admin"
	policy = <<EOT
path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
EOT
}

resource "vault_approle_auth_backend_role" "admin" {
    backend = vault_auth_backend.approle.path
	role_name = "admin"
	policies = [vault_policy.admin.name]
}

resource "vault_approle_auth_backend_role_secret_id" "admin" {
	backend = vault_auth_backend.approle.path
	role_name = vault_approle_auth_backend_role.admin.role_name
}
`
}

func testResourceApproleLoginCheckAttrs(t *testing.T) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_approle_auth_backend_role_secret_id.admin"]
		if resourceState == nil {
			return fmt.Errorf("approle secret id resource not found in state")
		}

		roleResourceState := s.Modules[0].Resources["vault_approle_auth_backend_role.admin"]
		if roleResourceState == nil {
			return fmt.Errorf("approle role resource not found in state")
		}

		backendResourceState := s.Modules[0].Resources["vault_auth_backend.approle"]
		if backendResourceState == nil {
			return fmt.Errorf("approle mount resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("approle secret id resource has no primary instance")
		}

		roleId := roleResourceState.Primary.Attributes["role_id"]
		secretId := instanceState.Attributes["secret_id"]

		authLoginData := []map[string]interface{}{
			{
				"path": "auth/approle/login",
				"parameters": map[string]interface{}{
					"role_id":   roleId,
					"secret_id": secretId,
				},
			},
		}
		approleProvider := Provider()
		approleProviderResource := &schema.Resource{
			Schema: approleProvider.Schema,
		}
		approleProviderData := approleProviderResource.TestResourceData()
		approleProviderData.Set("auth_login", authLoginData)
		_, err := providerConfigure(approleProviderData)
		if err != nil {
			t.Fatal(err)
		}
		return nil
	}
}

func testResourceAdminPeriodicOrphanTokenConfig_basic() string {
	return `
resource "vault_policy" "test" {
	name = "admin"
	policy = <<EOT
path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
EOT
}

resource "vault_token" "test" {
	policies = [ "${vault_policy.test.name}" ]
	ttl = "60s"
}`
}

func testResourceAdminPeriodicOrphanTokenCheckAttrs(namespacePath string, t *testing.T) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		//Check that it made the policy
		resourceState := s.Modules[0].Resources["vault_policy.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		//Check that it made the token and read it back

		tokenResourceState := s.Modules[0].Resources["vault_token.test"]
		if tokenResourceState == nil {
			return fmt.Errorf("token resource not found in state")
		}

		tokenInstanceState := tokenResourceState.Primary
		if tokenInstanceState == nil {
			return fmt.Errorf("token resource has no primary instance")
		}

		vaultToken := tokenResourceState.Primary.Attributes["client_token"]

		ns2Provider := Provider()
		ns2ProviderResource := &schema.Resource{
			Schema: ns2Provider.Schema,
		}
		ns2ProviderData := ns2ProviderResource.TestResourceData()
		ns2ProviderData.Set("namespace", namespacePath)
		ns2ProviderData.Set("token", vaultToken)
		if _, err := providerConfigure(ns2ProviderData); err != nil {
			t.Fatal(err)
		}

		ns2Path := acctest.RandomWithPrefix("test-namespace2")

		//Finally test that you can do stuff with the new token by creating a sub namespace
		resource.Test(t, resource.TestCase{
			PreCheck: func() { testAccPreCheck(t) },
			Providers: map[string]terraform.ResourceProvider{
				"vault": ns2Provider,
			},
			Steps: []resource.TestStep{
				{
					Config: testNamespaceConfig(ns2Path),
					Check:  testNamespaceCheckAttrs(),
				},
			},
		})

		return nil
	}
}

func TestAccProviderToken(t *testing.T) {
	// This is an acceptance test because it requires filesystem and env var
	// changes that could interfere with other Vault operations.
	if os.Getenv(resource.TestEnvVar) == "" {
		t.Skip(fmt.Sprintf(
			"Acceptance tests skipped unless env '%s' set",
			resource.TestEnvVar))
	}

	// Clear the token file if it exists and restore it after the test.
	tokenFilePath, err := homedir.Expand("~/.vault-token")
	if err != nil {
		t.Fatal(err)
	}
	origTokenBytes, err := ioutil.ReadFile(tokenFilePath)
	if err == nil {
		// There is an existing token file. Ensure it is restored after this test.
		info, err := os.Stat(tokenFilePath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			err := ioutil.WriteFile(tokenFilePath, origTokenBytes, info.Mode())
			if err != nil {
				t.Fatal(err)
			}
		}()
		// Delete the existing token file for a clean slate.
		if err := os.Remove(tokenFilePath); err != nil {
			t.Fatal(err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}

	// Clear the config file env var and restore it after the test.
	reset, err := tempUnsetenv(config.ConfigPathEnv)
	defer failIfErr(t, reset)
	if err != nil {
		t.Fatal(err)
	}

	// Create a "resource" we can use for constructing ResourceData.
	provider := Provider()
	providerResource := &schema.Resource{
		Schema: provider.Schema,
	}

	type testcase struct {
		name          string
		fileToken     bool
		helperToken   bool
		schemaToken   bool
		expectedToken string
	}

	tests := []testcase{
		{
			name:          "None",
			expectedToken: "",
		},
		{
			// The provider will read the token file "~/.vault-token".
			name:          "File",
			fileToken:     true,
			expectedToken: "file-token",
		},
		{
			// A custom token helper overrides token file.
			name:          "CustomHelper",
			fileToken:     true,
			helperToken:   true,
			expectedToken: "helper-token",
		},
		{
			// A VAULT_TOKEN env var or hardcoded token overrides all else.
			name:          "Schema",
			fileToken:     true,
			helperToken:   true,
			schemaToken:   true,
			expectedToken: "schema-token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set up the file token.
			if tc.fileToken {
				tokenBytes := []byte("file-token")
				err := ioutil.WriteFile(tokenFilePath, tokenBytes, 0666)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Remove(tokenFilePath); err != nil {
						t.Fatal(err)
					}
				}()
			}

			// Set up the custom helper token.
			if tc.helperToken {
				cleanup := setupTestTokenHelper(t, tokenHelperScript)
				defer cleanup()
			}

			d := providerResource.TestResourceData()
			// Set up the schema token.
			if tc.schemaToken {
				d.Set("token", "schema-token")
			}

			// Get and check the provider token.
			token, err := providerToken(d)
			if err != nil {
				t.Fatal(err)
			}
			if token != tc.expectedToken {
				t.Errorf("bad token value: want %#v, got %#v", tc.expectedToken, token)
			}
		})
	}
}

func TestAccTokenName(t *testing.T) {

	tests := []struct {
		TokenNameEnv       string
		UseTokenNameEnv    bool
		TokenNameSchema    string
		UseTokenNameSchema bool
		WantTokenName      string
	}{
		{
			UseTokenNameSchema: false,
			UseTokenNameEnv:    false,
			WantTokenName:      "token-terraform",
		},
		{
			TokenNameEnv:    "MyTokenName",
			UseTokenNameEnv: true,
			WantTokenName:   "token-MyTokenName",
		},
		{
			TokenNameEnv:    "",
			UseTokenNameEnv: true,
			WantTokenName:   "token-terraform",
		},
		{
			TokenNameSchema:    "",
			UseTokenNameSchema: true,
			WantTokenName:      "token-terraform",
		},
		{
			TokenNameEnv:    "My!TokenName",
			UseTokenNameEnv: true,
			WantTokenName:   "token-My-TokenName",
		},
		{
			TokenNameEnv:    "My!Token+*#Name",
			UseTokenNameEnv: true,
			WantTokenName:   "token-My-Token---Name",
		},
		{
			TokenNameSchema:    "MySchemaTokenName",
			UseTokenNameSchema: true,
			WantTokenName:      "token-MySchemaTokenName",
		},
		{
			TokenNameEnv:       "MyEnvTokenName",
			UseTokenNameEnv:    true,
			TokenNameSchema:    "MySchemaTokenName",
			UseTokenNameSchema: true,
			WantTokenName:      "token-MySchemaTokenName",
		},
	}

	for _, test := range tests {
		resource.Test(t, resource.TestCase{
			Providers: testProviders,
			PreCheck:  func() { testAccPreCheck(t) },
			Steps: []resource.TestStep{
				{
					PreConfig: func() {
						if test.UseTokenNameEnv {
							err := os.Setenv("VAULT_TOKEN_NAME", test.TokenNameEnv)
							if err != nil {
								t.Fatal(err)
							}
						} else {
							err := os.Unsetenv("VAULT_TOKEN_NAME")
							if err != nil {
								t.Fatal(err)
							}
						}
					},
					Config: testTokenNameConfig(test.UseTokenNameSchema, test.TokenNameSchema),
					Check:  testTokenName_check(test.WantTokenName),
				},
			},
		})
	}
}

func testHeaderConfig(headerName, headerValue string) string {
	providerConfig := fmt.Sprintf(`
	provider "vault" {
		headers {
			name  = "%s" 
			value = "%s"
		}
		token_name = "testtoken"
	}

	data "vault_generic_secret" "test" {
		path = "/auth/token/lookup-self"
	}
	`, headerName, headerValue)
	return providerConfig
}

// Using the data lookup generic_secret to inspect used token
// by terraform (this enables check of token name)
func testTokenNameConfig(tokenNameSchema bool, tokenName string) string {
	testConfig := ""
	providerConfig := `
provider "vault" {
    token_name = "` + tokenName + `"
}`

	dataConfig := `
data "vault_generic_secret" "test" {
    path = "/auth/token/lookup-self"
}
`
	if tokenNameSchema {
		testConfig = providerConfig + dataConfig
	} else {
		testConfig = dataConfig
	}
	return testConfig
}

func testTokenName_check(expectedTokenName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["data.vault_generic_secret.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
		}

		iState := resourceState.Primary
		if iState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		tokenName, ok := resourceState.Primary.Attributes["data.display_name"]
		if !ok {
			return fmt.Errorf("cannot access token [%s] for check", "display_name")
		}

		if tokenName != expectedTokenName {
			return fmt.Errorf("token name [%s] expected, but got [%s]", expectedTokenName, tokenName)
		}

		return nil
	}
}

// A token helper script that echos back the VAULT_ADDR value
const echoBackTokenHelperScript = `#!/usr/bin/env bash
printenv VAULT_ADDR
`

func TestAccProviderVaultAddrEnv(t *testing.T) {
	// This is an acceptance test because it requires filesystem and env var
	// changes that could interfere with other Vault operations.
	if os.Getenv(resource.TestEnvVar) == "" {
		t.Skip(fmt.Sprintf(
			"Acceptance tests skipped unless env '%s' set",
			resource.TestEnvVar))
	}

	// Clear the config file env var and restore it after the test.
	resetConfigPathEnv, err := tempUnsetenv(config.ConfigPathEnv)
	defer failIfErr(t, resetConfigPathEnv)
	if err != nil {
		t.Fatal(err)
	}

	// clear BASH_ENV for this test so any cmd.Exec invocations do not source the BASH_ENV
	// file which is configured with a VAULT_ADDR here:
	// https://github.com/terraform-providers/terraform-provider-vault/blob/f42716aae3aebc8daf9702dfa20ce3f8d09d9f4d/.circleci/config.yml#L27
	// All values set in that BASH_ENV file will still be in the process environment of this
	// test, they just won't clobber any values this test modifies in the process environment
	// when the ExternalTokenHelper's command is formatted into a shell invocation to exec here:
	// https://github.com/hashicorp/vault/blob/master/command/token/helper_external.go#L117-L132
	//
	resetBashEnvEnv, err := tempUnsetenv("BASH_ENV")
	defer failIfErr(t, resetBashEnvEnv)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		// vaultAddrEnv is set prior to the provider being instantiated or called
		// simulating any value the user or program may have in its existing environment
		vaultAddrEnv            string
		providerAddress         string
		providerAddAddressToEnv string
		expectedToken           string
	}{
		{
			// If add_address_to_env is not configured at all, do not add the address to the env
			name:                    "AddAddressToEnvNotConfigured",
			providerAddAddressToEnv: "",
			providerAddress:         "https://provider.example.com",
			vaultAddrEnv:            "https://pretest-env-var.example.com",
			expectedToken:           "https://pretest-env-var.example.com",
		},
		{
			name:                    "AddAddressToEnvIsFalse",
			providerAddAddressToEnv: "false",
			providerAddress:         "https://provider.example.com",
			vaultAddrEnv:            "https://pretest-env-var.example.com",
			expectedToken:           "https://pretest-env-var.example.com",
		},
		{
			name:                    "AddAddressToEnvIsTrue",
			providerAddAddressToEnv: "true",
			providerAddress:         "https://provider.example.com",
			vaultAddrEnv:            "https://pretest-env-var.example.com",
			expectedToken:           "https://provider.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			if tc.vaultAddrEnv != "" {
				unset, err := tempSetenv("VAULT_ADDR", tc.vaultAddrEnv)
				defer failIfErr(t, unset)
				if err != nil {
					t.Fatal(err)
				}
			}

			cleanup := setupTestTokenHelper(t, echoBackTokenHelperScript)
			defer cleanup()

			d, err := newTestResourceData(tc.providerAddress, tc.providerAddAddressToEnv)
			if err != nil {
				t.Fatal(err)
			}

			// Get and check the provider token.
			token, err := providerToken(d)
			if err != nil {
				t.Fatal(err)
			}
			if token != tc.expectedToken {
				t.Errorf("bad token value: want %#v, got %#v", tc.expectedToken, token)
			}
		})
	}
}

func newTestResourceData(address string, addAddressToEnv string) (*schema.ResourceData, error) {
	// Create a "resource" we can use for constructing ResourceData.
	provider := Provider()
	providerResource := &schema.Resource{
		Schema: provider.Schema,
		// this needs to be configured with and without add_Address_to_env
	}

	d := providerResource.TestResourceData()
	err := d.Set("address", address)
	if err != nil {
		return nil, err
	}

	if addAddressToEnv != "" {
		err = d.Set("add_address_to_env", addAddressToEnv)
		if err != nil {
			return nil, err
		}
	}

	return d, nil
}

func failIfErr(t *testing.T, f func() error) {
	if err := f(); err != nil {
		t.Fatal(err)
	}
}

// tempUnsetenv is the equivalent of calling `os.Unsetenv` but returns
// a function that be called to restore the modified environment variable
// to its state prior to this function being called.
// The reset function will never be nil.
func tempUnsetenv(key string) (reset func() error, err error) {
	reset = resetEnvFunc(key)
	err = os.Unsetenv(key)
	return reset, err
}

// tempSetenv is the equivalent of calling `os.Setenv` but returns
// a function that be called to restore the modified environment variable
// to its state prior to this function being called.
// The reset function will never be nil.
func tempSetenv(key string, value string) (reset func() error, err error) {
	reset = resetEnvFunc(key)
	err = os.Setenv(key, value)
	return reset, err
}

// resetEnvFunc returns a func that will reset the state of
// the environment variable named `key` when it is called to the
// state captured at the time the function was created
func resetEnvFunc(key string) (reset func() error) {
	if current, exists := os.LookupEnv(key); exists {
		return func() error {
			return os.Setenv(key, current)
		}
	} else {
		return func() error {
			return os.Unsetenv(key)
		}
	}
}

// setupTestTokenHelper creates a temporary vault config that uses the provided
// script as a token helper and returns a cleanup function that should be deferred and
// called to set back the environment to how it was were pre test.
func setupTestTokenHelper(t *testing.T, script string) (cleanup func()) {
	// Use a temp dir for test files.
	dir, err := ioutil.TempDir("", "terraform-provider-vault")
	if err != nil {
		t.Fatal(err)
	}

	// Write out the config file and helper script file.
	configPath := path.Join(dir, "vault-config")
	helperPath := path.Join(dir, "helper-script")
	configStr := fmt.Sprintf(`token_helper = "%s"`, helperPath)
	err = ioutil.WriteFile(configPath, []byte(configStr), 0666)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(helperPath, []byte(script), 0777)
	if err != nil {
		t.Fatal(err)
	}
	// Point Vault at the config file.
	os.Setenv(config.ConfigPathEnv, configPath)
	if err != nil {
		t.Fatal(err)
	}

	return func() {
		if err := os.Unsetenv(config.ConfigPathEnv); err != nil {
			t.Fatal(err)
		}

		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
}

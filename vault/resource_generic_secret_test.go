package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourceGenericSecret(t *testing.T) {
	path := acctest.RandomWithPrefix("secretsv1/test")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(path),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				Config: testResourceGenericSecret_updateConfig,
				Check:  testResourceGenericSecret_updateCheck,
			},
		},
	})
}

func TestResourceGenericSecret_deleted(t *testing.T) {
	path := acctest.RandomWithPrefix("secretsv1/test")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(path),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*api.Client)
					_, err := client.Logical().Delete(path)
					if err != nil {
						t.Fatalf("unable to manually delete the secret via the SDK: %s", err)
					}
				},
				Config: testResourceGenericSecret_initialConfig(path),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
		},
	})
}

func TestResourceGenericSecret_kvV2_deleted(t *testing.T) {
	path := acctest.RandomWithPrefix("secretsv2/test")
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_kvV2_initialConfig(path),
				Check:  testResourceGenericSecret_kvV2_initialCheck(path),
			},
			{
				PreConfig: func() {
					client := testProvider.Meta().(*api.Client)
					_, err := client.Logical().Delete("secretsv2/metadata/test")
					if err != nil {
						t.Fatalf("unable to manually delete the secret via the SDK: %s", err)
					}
				},
				Config: testResourceGenericSecret_kvV2_initialConfig(path),
				Check:  testResourceGenericSecret_kvV2_initialCheck(path),
			},
		},
	})
}

func testResourceGenericSecret_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "v1" {
	path = "secretsv1"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
    depends_on = ["vault_mount.v1"]
    path = "%s"
    data_json = <<EOT
{
    "zip": "zap"
}
EOT
}`, path)
}

func testResourceGenericSecret_kvV2_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "v2" {
	path = "secretsv2"
	type = "kv"
	options = {
		version = "2"
	}
}

resource "vault_generic_secret" "test" {
    depends_on = ["vault_mount.v2"]
	path = "%s"
	delete_all_versions = true
    data_json = <<EOT
{
    "zoop": "ziip"
}
EOT
}`, path)
}

func testResourceGenericSecret_initialCheck(expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_generic_secret.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := instanceState.ID

		if path != instanceState.Attributes["path"] {
			return fmt.Errorf("id doesn't match path")
		}
		if path != expectedPath {
			return fmt.Errorf("unexpected secret path")
		}

		client := testProvider.Meta().(*api.Client)
		secret, err := client.Logical().Read(path)
		if err != nil {
			return fmt.Errorf("error reading back secret: %s", err)
		}

		// Test the JSON
		if got, want := secret.Data["zip"], "zap"; got != want {
			return fmt.Errorf("'zip' data is %q; want %q", got, want)
		}

		// Test the map
		if got, want := instanceState.Attributes["data.zip"], "zap"; got != want {
			return fmt.Errorf("data[\"zip\"] contains %s; want %s", got, want)
		}

		return nil
	}
}
func testResourceGenericSecret_kvV2_initialCheck(expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_generic_secret.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := instanceState.ID

		if path != instanceState.Attributes["path"] {
			return fmt.Errorf("id doesn't match path")
		}
		if path != expectedPath {
			return fmt.Errorf("unexpected secret path")
		}

		client := testProvider.Meta().(*api.Client)
		secretList, err := client.Logical().List("secretsv2/metadata")
		if err != nil {
			return fmt.Errorf("error reading back secrets: %s", err)
		}

		if secretList == nil {
			return fmt.Errorf("no kv-v2 secrets, expected one")
		}
		keys := secretList.Data["keys"].([]interface{})
		secret, err := client.Logical().Read(fmt.Sprintf("secretsv2/data/%s", keys[0]))
		if secret == nil {
			return fmt.Errorf("no kv-v2 secret, expected one.")
		}
		// Test the JSON.  Kv-v2 data is nested one level deeper than kv-v1.
		nestedData := secret.Data["data"].(map[string]interface{})
		if got, want := nestedData["zoop"].(string), "ziip"; got != want {
			return fmt.Errorf("'zoop' data is %q; want %q", got, want)
		}

		// Test the map
		if got, want := instanceState.Attributes["data.zoop"], "ziip"; got != want {
			return fmt.Errorf("data[\"zoop\"] contains %s; want %s", got, want)
		}

		return nil
	}
}

var testResourceGenericSecret_updateConfig = `

resource "vault_mount" "v1" {
	path = "secretsv1"
	type = "kv"
	options = {
		version = "1"
	}
}

resource "vault_generic_secret" "test" {
    path = "${vault_mount.v1.path}/foo"
    disable_read = false
    data_json = <<EOT
{
    "zip": "zoop"
}
EOT
}

`

func testResourceGenericSecret_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_generic_secret.test"]
	instanceState := resourceState.Primary

	path := instanceState.ID

	client := testProvider.Meta().(*api.Client)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading back secret: %s", err)
	}

	if got, want := secret.Data["zip"], "zoop"; got != want {
		return fmt.Errorf("'zip' data is %q; want %q", got, want)
	}

	return nil
}

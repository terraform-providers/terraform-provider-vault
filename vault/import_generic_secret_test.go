package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
)

func TestAccGenericSecret_importBasic(t *testing.T) {
	path := acctest.RandomWithPrefix("secretsv1/test-")
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testResourceGenericSecret_initialConfig(path),
				Check:  testResourceGenericSecret_initialCheck(path),
			},
			{
				ResourceName:            "vault_generic_secret.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"delete_all_versions"},
			},
		},
	})
}

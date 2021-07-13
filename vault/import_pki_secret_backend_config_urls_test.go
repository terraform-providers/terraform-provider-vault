package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func TestAccPkiSecretBackend_importBasic(t *testing.T) {
	path := "test-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendCertConfigUrlsConfig_basic(path, "http://the_issuer", "http://crl", "http://ocsp"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_config_urls.test", "issuing_certificates.0", "http://the_issuer"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_config_urls.test", "crl_distribution_points.0", "http://crl"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_config_urls.test", "ocsp_servers.0", "http://ocsp"),
				),
			},
			{
				ResourceName:      "vault_pki_secret_backend_config_urls.test",
				ImportState:       true,
				ImportStateIdFunc: testAccPkiSecretBackendImportStateIdFunc("vault_pki_secret_backend_config_urls.test"),
				ImportStateVerify: true,
				ImportStateCheck: func(s []*terraform.InstanceState) error {
					if len(s) != 1 {
						return fmt.Errorf("expected 1 state: %#v", s)
					}
					rs := s[0]

					if !strings.HasSuffix(rs.Attributes["id"], "/config/urls") {
						return fmt.Errorf("expected id attribute to be set and end with /config/urls, received: %s", rs.Attributes["id"])
					}

					if !strings.HasPrefix(rs.Attributes["id"], rs.Attributes["backend"]) {
						return fmt.Errorf("expected id attribute to start with the backend name %s, received: %s", rs.Attributes["backend"], rs.Attributes["id"])
					}

					return nil
				},
			},
		},
	})
}

func testAccPkiSecretBackendImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("Not found: %s", resourceName)
		}

		return rs.Primary.Attributes["backend"], nil
	}
}

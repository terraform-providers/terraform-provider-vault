package vault

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestPkiSecretBackendCert_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendCertDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendCertConfig_basic(rootPath, intermediatePath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "backend", intermediatePath),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "common_name", "cert.test.my.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "ttl", "720h"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "uri_sans.#", "1"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "uri_sans.0", "spiffe://test.my.domain"),
				),
			},
		},
	})
}

func testPkiSecretBackendCertDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_pki_secret_backend" {
			continue
		}
		for path, mount := range mounts {
			path = strings.Trim(path, "/")
			rsPath := strings.Trim(rs.Primary.Attributes["path"], "/")
			if mount.Type == "pki" && path == rsPath {
				return fmt.Errorf("Mount %q still exists", path)
			}
		}
	}
	return nil
}

func testPkiSecretBackendCertConfig_basic(rootPath string, intermediatePath string) string {
	return fmt.Sprintf(`
resource "vault_pki_secret_backend" "test-root" {
  path = "%s"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds = "8640000"
}

resource "vault_pki_secret_backend" "test-intermediate" {
  depends_on = [ "vault_pki_secret_backend.test-root" ]
  path = "%s"
  description = "test intermediate"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  depends_on = [ "vault_pki_secret_backend.test-intermediate" ]
  backend = "${vault_pki_secret_backend.test-root.path}"
  type = "internal"
  common_name = "my.domain"
  ttl = "86400"
  format = "pem"
  private_key_format = "der"
  key_type = "rsa"
  key_bits = 4096
  ou = "test"
  organization = "test"
  country = "test"
  locality = "test"
  province = "test"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  depends_on = [ "vault_pki_secret_backend_root_cert.test" ]
  backend = "${vault_pki_secret_backend.test-intermediate.path}"
  type = "internal"
  common_name = "test.my.domain"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "test" {
  depends_on = [ "vault_pki_secret_backend_intermediate_cert_request.test" ]
  backend = "${vault_pki_secret_backend.test-root.path}"
  csr = "${vault_pki_secret_backend_intermediate_cert_request.test.csr}"
  common_name = "test.my.domain"
  permitted_dns_domains = [".test.my.domain"]
  ou = "test"
  organization = "test"
  country = "test"
  locality = "test"
  province = "test"
}

resource "vault_pki_secret_backend_intermediate_set_signed" "test" {
  depends_on = [ "vault_pki_secret_backend_root_sign_intermediate.test" ]
  backend = "${vault_pki_secret_backend.test-intermediate.path}"
  certificate = "${vault_pki_secret_backend_root_sign_intermediate.test.certificate}"
}

resource "vault_pki_secret_backend_role" "test" {
  depends_on = [ "vault_pki_secret_backend_intermediate_set_signed.test" ]
  backend = "${vault_pki_secret_backend.test-intermediate.path}"
  name = "test"
  allowed_domains  = ["test.my.domain"]
  allow_subdomains = true
  allowed_uri_sans = ["spiffe://test.my.domain"]
  max_ttl = "3600"
  key_usage = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
}

resource "vault_pki_secret_backend_cert" "test" {
  depends_on = [ "vault_pki_secret_backend_role.test" ]
  backend = "${vault_pki_secret_backend.test-intermediate.path}"
  name = "${vault_pki_secret_backend_role.test.name}"
  common_name = "cert.test.my.domain"
  uri_sans = ["spiffe://test.my.domain"]
  ttl = "720h"
  min_seconds_remaining = 60
}`, rootPath, intermediatePath)
}

func TestPkiSecretBackendCert_renew(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendCertDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendCertConfig_renew(rootPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "backend", rootPath),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "common_name", "cert.test.my.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "ttl", "1h"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "min_seconds_remaining", "3595"),
					resource.TestCheckResourceAttrSet("vault_pki_secret_backend_cert.test", "expiration"),
				),
			},
			{
				Config:   testPkiSecretBackendCertConfig_renew(rootPath),
				PlanOnly: true,
			},
			{
				Config: testPkiSecretBackendCertConfig_renew(rootPath),
				Check: resource.ComposeTestCheckFunc(
					testPkiSecretBackendCertWaitUntilRenewal("vault_pki_secret_backend_cert.test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "backend", rootPath),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "common_name", "cert.test.my.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "ttl", "1h"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "min_seconds_remaining", "3595"),
					resource.TestCheckResourceAttrSet("vault_pki_secret_backend_cert.test", "expiration"),
				),
				ExpectNonEmptyPlan: true,
			},
			{
				Config: testPkiSecretBackendCertConfig_renew(rootPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "backend", rootPath),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "common_name", "cert.test.my.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "ttl", "1h"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_cert.test", "min_seconds_remaining", "3595"),
					resource.TestCheckResourceAttrSet("vault_pki_secret_backend_cert.test", "expiration"),
				),
			},
		},
	})
}

func testPkiSecretBackendCertConfig_renew(rootPath string) string {
	return fmt.Sprintf(`
resource "vault_pki_secret_backend" "test-root" {
  path = "%s"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds = "8640000"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  depends_on = [ "vault_pki_secret_backend.test-root" ]
  backend = "${vault_pki_secret_backend.test-root.path}"
  type = "internal"
  common_name = "my.domain"
  ttl = "86400"
  format = "pem"
  private_key_format = "der"
  key_type = "rsa"
  key_bits = 4096
  ou = "test"
  organization = "test"
  country = "test"
  locality = "test"
  province = "test"
}

resource "vault_pki_secret_backend_role" "test" {
  depends_on = [ "vault_pki_secret_backend_root_cert.test" ]
  backend = "${vault_pki_secret_backend.test-root.path}"
  name = "test"
  allowed_domains  = ["test.my.domain"]
  allow_subdomains = true
  max_ttl = "3600"
  key_usage = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
}

resource "vault_pki_secret_backend_cert" "test" {
  depends_on = [ "vault_pki_secret_backend_role.test" ]
  backend = "${vault_pki_secret_backend.test-root.path}"
  name = "${vault_pki_secret_backend_role.test.name}"
  common_name = "cert.test.my.domain"
  ttl = "1h"
  auto_renew = true
  min_seconds_remaining = "3595"
}`, rootPath)
}

func testPkiSecretBackendCertWaitUntilRenewal(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		expiration, err := strconv.Atoi(rs.Primary.Attributes["expiration"])
		if err != nil {
			return fmt.Errorf("Invalid expiration value: %s", err)
		}

		minSecondsRemain, err := strconv.Atoi(rs.Primary.Attributes["min_seconds_remaining"])
		if err != nil {
			return fmt.Errorf("Invalid min_seconds_remaining value: %s", err)
		}

		secondsUntilRenewal := expiration - (int(time.Now().Unix()) + minSecondsRemain)
		time.Sleep(time.Duration(secondsUntilRenewal+1) * time.Second)

		return nil
	}
}

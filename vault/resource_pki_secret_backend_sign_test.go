package vault

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestPkiSecretBackendSign_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendSignDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendSignConfig_basic(rootPath, intermediatePath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "backend", intermediatePath),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "common_name", "cert.test.my.domain"),
				),
			},
		},
	})
}

func testPkiSecretBackendSignDestroy(s *terraform.State) error {
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

func testPkiSecretBackendSignConfig_basic(rootPath string, intermediatePath string) string {
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
  max_ttl = "3600"
  key_usage = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
}

resource "vault_pki_secret_backend_sign" "test" {
  depends_on = [ "vault_pki_secret_backend_role.test" ]
  backend = "${vault_pki_secret_backend.test-intermediate.path}"
  name = "${vault_pki_secret_backend_role.test.name}"
  csr = <<EOT
-----BEGIN CERTIFICATE REQUEST-----
MIIEqDCCApACAQAwYzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEcMBoGA1UEAwwTY2Vy
dC50ZXN0Lm15LmRvbWFpbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AJupYCQ8UVCWII1Zof1c6YcSSaM9hEaDU78cfKP5RoSeH10BvrWRfT+mzCONVpNP
CW9Iabtvk6hm0ot6ilnndEyVJbc0g7hdDLBX5BM25D+DGZGJRKUz1V+uBrWmXtIt
Vonj7JTDTe7ViH0GDsB7CvqXFGXO2a2cDYBchLkL6vQiFPshxvUsLtwxuy/qdYgy
X6ya+AUoZcoQGy1XxNjfH6cPtWSWQGEp1oPR6vL9hU3laTZb3C+VV4jZem+he8/0
V+qV6fLG92WTXm2hmf8nrtUqqJ+C7mW/RJod+TviviBadIX0OHXW7k5HVsZood01
te8vMRUNJNiZfa9EMIK5oncbQn0LcM3Wo9VrjpL7jREb/4HCS2gswYGv7hzk9cCS
kVY4rDucchKbApuI3kfzmO7GFOF5eiSkYZpY/czNn7VVM3WCu6dpOX4+3rhgrZQw
kY14L930DaLVRUgve/zKVP2D2GHdEOs+MbV7s96UgigT9pXly/yHPj+1sSYqmnaD
5b7jSeJusmzO/nrwXVGLsnezR87VzHl9Ux9g5s6zh+R+PrZuVxYsLvoUpaasH47O
gIcBzSb/6pSGZKAUizmYsHsR1k88dAvsQ+FsUDaNokdi9VndEB4QPmiFmjyLV+0I
1TFoXop4sW11NPz1YCq+IxnYrEaIN3PyhY0GvBJDFY1/AgMBAAGgADANBgkqhkiG
9w0BAQsFAAOCAgEActuqnqS8Y9UF7e08w7tR3FPzGecWreuvxILrlFEZJxiLPFqL
It7uJvtypCVQvz6UQzKdBYO7tMpRaWViB8DrWzXNZjLMrg+QHcpveg8C0Ett4scG
fnvLk6fTDFYrnGvwHTqiHos5i0y3bFLyS1BGwSpdLAykGtvC+VM8mRyw/Y7CPcKN
77kebY/9xduW1g2uxWLr0x90RuQDv9psPojT+59tRLGSp5Kt0IeD3QtnAZEFE4aN
vt+Pd69eg3BgZ8ZeDgoqAw3yppvOkpAFiE5pw2qPZaM4SRphl4d2Lek2zNIMyZqv
do5zh356HOgXtDaSg0POnRGrN/Ua+LMCRTg6GEPUnx9uQb/zt8Zu0hIexDGyykp1
OGqtWlv/Nc8UYuS38v0BeB6bMPeoqQUjkqs8nHlAEFn0KlgYdtDC+7SdQx6wS4te
dBKRNDfC4lS3jYJgs55jHqonZgkpSi3bamlxpfpW0ukGBcmq91wRe4bOw/4uD/vf
UwqMWOdCYcU3mdYNjTWy22ORW3SGFQxMBwpUEURCSoeqWr6aJeQ7KAYkx1PrB5T8
OTEc13lWf+B0PU9UJuGTsmpIuImPDVd0EVDayr3mT5dDbqTVDbe8ppf2IswABmf0
o3DybUeUmknYjl109rdSf+76nuREICHatxXgN3xCMFuBaN4WLO+ksd6Y1Ys=
-----END CERTIFICATE REQUEST-----
EOT
  common_name = "cert.test.my.domain"
}`, rootPath, intermediatePath)
}

func TestPkiSecretBackendSign_renew(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testPkiSecretBackendCertDestroy,
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendSignConfig_renew(rootPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "backend", rootPath),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "common_name", "cert.test.my.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "ttl", "1h"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "min_seconds_remaining", "3595"),
					resource.TestCheckResourceAttrSet("vault_pki_secret_backend_sign.test", "expiration"),
					resource.TestCheckResourceAttrSet("vault_pki_secret_backend_sign.test", "serial"),
				),
			},
			{
				Config:   testPkiSecretBackendSignConfig_renew(rootPath),
				PlanOnly: true,
			},
			{
				Config: testPkiSecretBackendSignConfig_renew(rootPath),
				Check: resource.ComposeTestCheckFunc(
					testPkiSecretBackendSignWaitUntilRenewal("vault_pki_secret_backend_sign.test"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "backend", rootPath),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "common_name", "cert.test.my.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "ttl", "1h"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "min_seconds_remaining", "3595"),
					resource.TestCheckResourceAttrSet("vault_pki_secret_backend_sign.test", "expiration"),
					resource.TestCheckResourceAttrSet("vault_pki_secret_backend_sign.test", "serial"),
				),
				ExpectNonEmptyPlan: true,
			},
			{
				Config: testPkiSecretBackendSignConfig_renew(rootPath),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "backend", rootPath),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "common_name", "cert.test.my.domain"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "ttl", "1h"),
					resource.TestCheckResourceAttr("vault_pki_secret_backend_sign.test", "min_seconds_remaining", "3595"),
					resource.TestCheckResourceAttrSet("vault_pki_secret_backend_sign.test", "expiration"),
					resource.TestCheckResourceAttrSet("vault_pki_secret_backend_sign.test", "serial"),
				),
			},
		},
	})
}

func testPkiSecretBackendSignConfig_renew(rootPath string) string {
	return fmt.Sprintf(`
resource "vault_pki_secret_backend" "test-root" {
  path = "%s"
  description = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds = "8640000"
}

resource "vault_pki_secret_backend_root_cert" "test" {
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

resource "vault_pki_secret_backend_sign" "test" {
  depends_on = [ "vault_pki_secret_backend_role.test" ]
  backend = "${vault_pki_secret_backend.test-root.path}"
  name = "${vault_pki_secret_backend_role.test.name}"
  csr = <<EOT
-----BEGIN CERTIFICATE REQUEST-----
MIIEqDCCApACAQAwYzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEcMBoGA1UEAwwTY2Vy
dC50ZXN0Lm15LmRvbWFpbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AJupYCQ8UVCWII1Zof1c6YcSSaM9hEaDU78cfKP5RoSeH10BvrWRfT+mzCONVpNP
CW9Iabtvk6hm0ot6ilnndEyVJbc0g7hdDLBX5BM25D+DGZGJRKUz1V+uBrWmXtIt
Vonj7JTDTe7ViH0GDsB7CvqXFGXO2a2cDYBchLkL6vQiFPshxvUsLtwxuy/qdYgy
X6ya+AUoZcoQGy1XxNjfH6cPtWSWQGEp1oPR6vL9hU3laTZb3C+VV4jZem+he8/0
V+qV6fLG92WTXm2hmf8nrtUqqJ+C7mW/RJod+TviviBadIX0OHXW7k5HVsZood01
te8vMRUNJNiZfa9EMIK5oncbQn0LcM3Wo9VrjpL7jREb/4HCS2gswYGv7hzk9cCS
kVY4rDucchKbApuI3kfzmO7GFOF5eiSkYZpY/czNn7VVM3WCu6dpOX4+3rhgrZQw
kY14L930DaLVRUgve/zKVP2D2GHdEOs+MbV7s96UgigT9pXly/yHPj+1sSYqmnaD
5b7jSeJusmzO/nrwXVGLsnezR87VzHl9Ux9g5s6zh+R+PrZuVxYsLvoUpaasH47O
gIcBzSb/6pSGZKAUizmYsHsR1k88dAvsQ+FsUDaNokdi9VndEB4QPmiFmjyLV+0I
1TFoXop4sW11NPz1YCq+IxnYrEaIN3PyhY0GvBJDFY1/AgMBAAGgADANBgkqhkiG
9w0BAQsFAAOCAgEActuqnqS8Y9UF7e08w7tR3FPzGecWreuvxILrlFEZJxiLPFqL
It7uJvtypCVQvz6UQzKdBYO7tMpRaWViB8DrWzXNZjLMrg+QHcpveg8C0Ett4scG
fnvLk6fTDFYrnGvwHTqiHos5i0y3bFLyS1BGwSpdLAykGtvC+VM8mRyw/Y7CPcKN
77kebY/9xduW1g2uxWLr0x90RuQDv9psPojT+59tRLGSp5Kt0IeD3QtnAZEFE4aN
vt+Pd69eg3BgZ8ZeDgoqAw3yppvOkpAFiE5pw2qPZaM4SRphl4d2Lek2zNIMyZqv
do5zh356HOgXtDaSg0POnRGrN/Ua+LMCRTg6GEPUnx9uQb/zt8Zu0hIexDGyykp1
OGqtWlv/Nc8UYuS38v0BeB6bMPeoqQUjkqs8nHlAEFn0KlgYdtDC+7SdQx6wS4te
dBKRNDfC4lS3jYJgs55jHqonZgkpSi3bamlxpfpW0ukGBcmq91wRe4bOw/4uD/vf
UwqMWOdCYcU3mdYNjTWy22ORW3SGFQxMBwpUEURCSoeqWr6aJeQ7KAYkx1PrB5T8
OTEc13lWf+B0PU9UJuGTsmpIuImPDVd0EVDayr3mT5dDbqTVDbe8ppf2IswABmf0
o3DybUeUmknYjl109rdSf+76nuREICHatxXgN3xCMFuBaN4WLO+ksd6Y1Ys=
-----END CERTIFICATE REQUEST-----
EOT
  common_name = "cert.test.my.domain"
  ttl = "1h"
  auto_renew = true
  min_seconds_remaining = "3595"
}`, rootPath)
}

func testPkiSecretBackendSignWaitUntilRenewal(n string) resource.TestCheckFunc {
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

package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
	"strconv"
	"testing"
	"time"
)

func testResourceTokenCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_token" {
			continue
		}
		_, err := client.Auth().Token().LookupAccessor(rs.Primary.ID)
		if err == nil {
			return fmt.Errorf("token with accessor %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func TestResourceToken_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token.test", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_token.test", "ttl", "60s"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_duration"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_started"),
					resource.TestCheckResourceAttrSet("vault_token.test", "client_token"),
					resource.TestCheckResourceAttr("vault_token.test", "encrypted_client_token", ""),
				),
			},
		},
	})
}

func TestResourceToken_import(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_basic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token.test", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_token.test", "ttl", "60s"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_duration"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_started"),
					resource.TestCheckResourceAttrSet("vault_token.test", "client_token"),
					resource.TestCheckResourceAttr("vault_token.test", "encrypted_client_token", ""),
				),
			},
			{
				ResourceName:      "vault_token.test",
				ImportState:       true,
				ImportStateVerify: true,
				// the API can't serve these fields, so ignore them
				ImportStateVerifyIgnore: []string{"ttl", "lease_duration", "lease_started", "client_token", "encrypted_client_token"},
			},
		},
	})
}

func testResourceTokenConfig_basic() string {
	return `
resource "vault_policy" "test" {
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
	policies = [ "${vault_policy.test.name}" ]
	ttl = "60s"
}`
}

func TestResourceToken_full(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_full(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token.test", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_token.test", "no_parent", "true"),
					resource.TestCheckResourceAttr("vault_token.test", "no_default_policy", "true"),
					resource.TestCheckResourceAttr("vault_token.test", "renewable", "true"),
					resource.TestCheckResourceAttr("vault_token.test", "ttl", "60s"),
					resource.TestCheckResourceAttr("vault_token.test", "explicit_max_ttl", "1h"),
					resource.TestCheckResourceAttr("vault_token.test", "display_name", "test"),
					resource.TestCheckResourceAttr("vault_token.test", "num_uses", "1"),
					resource.TestCheckResourceAttr("vault_token.test", "period", "0"),
					resource.TestCheckResourceAttr("vault_token.test", "lease_duration", "59"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_started"),
					resource.TestCheckResourceAttrSet("vault_token.test", "client_token"),
					resource.TestCheckResourceAttr("vault_token.test", "encrypted_client_token", ""),
					resource.TestCheckResourceAttr("vault_token.test", "metadata.fizz", "buzz"),
				),
			},
		},
	})
}

func testResourceTokenConfig_full() string {
	return `
resource "vault_policy" "test" {
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
	policies = [ "${vault_policy.test.name}" ]
	no_parent = true
    no_default_policy = true
	renewable = true
	ttl = "60s"
    explicit_max_ttl = "1h"
    display_name = "test"
    num_uses = 1
	period = 0
	metadata = {
		fizz = "buzz"
	}
}`
}

func TestResourceToken_lookup(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_lookup(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenLookup("vault_token.test"),
				),
			},
		},
	})
}

func testResourceTokenConfig_lookup() string {
	return `
resource "vault_policy" "test" {
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
	policies = [ "${vault_policy.test.name}" ]
	ttl = "60s"
}`
}

func TestResourceToken_expire(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_expire(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenCheckExpireTime("vault_token.test"),
					resource.TestCheckResourceAttr("vault_token.test", "ttl", "10s"),
					resource.TestCheckResourceAttr("vault_token.test", "lease_duration", "9"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_started"),
					resource.TestCheckResourceAttrSet("vault_token.test", "client_token"),
				),
			},
			{
				Config:   testResourceTokenConfig_expire(),
				PlanOnly: true,
			},
			{
				Config: testResourceTokenConfig_expire(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenWaitExpireTime("vault_token.test"),
				),
				ExpectNonEmptyPlan: true,
			},
			{
				Config:  testResourceTokenConfig_expire(),
				Destroy: true,
			},
			{
				Config: testResourceTokenConfig_expire(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenCheckExpireTime("vault_token.test"),
					resource.TestCheckResourceAttr("vault_token.test", "ttl", "10s"),
					resource.TestCheckResourceAttr("vault_token.test", "lease_duration", "9"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_started"),
					resource.TestCheckResourceAttrSet("vault_token.test", "client_token"),
					resource.TestCheckResourceAttr("vault_token.test", "encrypted_client_token", ""),
				),
			},
		},
	})
}

func testResourceTokenConfig_expire() string {
	return `
resource "vault_policy" "test" {
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
	policies = [ "${vault_policy.test.name}" ]
	ttl = "10s"
}`
}

func TestResourceToken_renew(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_renew(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenCheckExpireTime("vault_token.test"),
					resource.TestCheckResourceAttr("vault_token.test", "ttl", "30s"),
					resource.TestCheckResourceAttr("vault_token.test", "renew_min_lease", "10"),
					resource.TestCheckResourceAttr("vault_token.test", "renew_increment", "30"),
					resource.TestCheckResourceAttr("vault_token.test", "lease_duration", "29"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_started"),
					resource.TestCheckResourceAttrSet("vault_token.test", "client_token"),
					resource.TestCheckResourceAttr("vault_token.test", "encrypted_client_token", ""),
				),
			},
			{
				Config:   testResourceTokenConfig_renew(),
				PlanOnly: true,
			},
			{
				Config: testResourceTokenConfig_renew(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenWaitRenewMinLeaseTime("vault_token.test"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_duration"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_started"),
					resource.TestCheckResourceAttrSet("vault_token.test", "client_token"),
					resource.TestCheckResourceAttr("vault_token.test", "encrypted_client_token", ""),
				),
			},
			{
				Config:  testResourceTokenConfig_renew(),
				Destroy: true,
			},
			{
				Config: testResourceTokenConfig_renew(),
				Check: resource.ComposeTestCheckFunc(
					testResourceTokenCheckExpireTime("vault_token.test"),
					resource.TestCheckResourceAttr("vault_token.test", "ttl", "30s"),
					resource.TestCheckResourceAttr("vault_token.test", "renew_min_lease", "10"),
					resource.TestCheckResourceAttr("vault_token.test", "renew_increment", "30"),
					resource.TestCheckResourceAttr("vault_token.test", "lease_duration", "29"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_started"),
					resource.TestCheckResourceAttrSet("vault_token.test", "client_token"),
					resource.TestCheckResourceAttr("vault_token.test", "encrypted_client_token", ""),
				),
			},
		},
	})
}

func testResourceTokenConfig_renew() string {
	return `
resource "vault_policy" "test" {
	name = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
	policies = [ "${vault_policy.test.name}" ]
	renewable = true
	ttl = "30s"
	renew_min_lease = 10
	renew_increment = 30
}`
}

func testResourceTokenLookup(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		client := testProvider.Meta().(*api.Client)

		_, err := client.Auth().Token().LookupAccessor(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Token could not be found: %s", err)
		}

		return nil
	}
}

func testResourceTokenCheckExpireTime(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		client := testProvider.Meta().(*api.Client)

		token, err := client.Auth().Token().LookupAccessor(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Token could not be found: %s", err)
		}

		expireTime, err := time.Parse(time.RFC3339, token.Data["expire_time"].(string))
		if err != nil {
			return fmt.Errorf("Invalid expire_time value: %s", err)
		}

		startedTime, err := time.Parse(time.RFC3339, rs.Primary.Attributes["lease_started"])
		if err != nil {
			return fmt.Errorf("Invalid lease_started value: %s", err)
		}

		if startedTime.After(time.Now()) {
			return fmt.Errorf("Invalid lease_started value: %s", "time is in the future")
		}

		leaseDuration, err := strconv.Atoi(rs.Primary.Attributes["lease_duration"])
		if err != nil {
			return fmt.Errorf("Invalid lease_duration value: %s", err)
		}

		leaseTime := startedTime.Add(time.Duration(leaseDuration) * time.Second)

		if leaseTime.After(expireTime) {
			return fmt.Errorf("Lease time %s is after expire time %s", leaseTime, expireTime)
		}

		return nil
	}
}

func testResourceTokenWaitExpireTime(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		leaseDuration, err := strconv.Atoi(rs.Primary.Attributes["lease_duration"])
		if err != nil {
			return fmt.Errorf("Invalid lease_duration value: %s", err)
		}

		time.Sleep(time.Duration(leaseDuration+1) * time.Second)

		return nil
	}
}

func testResourceTokenWaitRenewMinLeaseTime(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		client := testProvider.Meta().(*api.Client)

		token, err := client.Auth().Token().LookupAccessor(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("Token could not be found: %s", err)
		}

		if !token.Data["renewable"].(bool) {
			return fmt.Errorf("Token could not be renewed")
		}

		leaseDuration, err := strconv.Atoi(rs.Primary.Attributes["lease_duration"])
		if err != nil {
			return fmt.Errorf("Invalid lease_duration value: %s", err)
		}

		renewMinLease, err := strconv.Atoi(rs.Primary.Attributes["renew_min_lease"])
		if err != nil {
			return fmt.Errorf("Invalid renew_min_lease value: %s", err)
		}

		time.Sleep(time.Duration(leaseDuration-renewMinLease+1) * time.Second)

		return nil
	}
}

func TestResourceToken_pgp(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testResourceTokenCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testResourceTokenConfig_pgp(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_token.test", "policies.#", "1"),
					resource.TestCheckResourceAttr("vault_token.test", "ttl", "60s"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_duration"),
					resource.TestCheckResourceAttrSet("vault_token.test", "lease_started"),
					resource.TestCheckResourceAttr("vault_token.test", "client_token", ""),
					resource.TestCheckResourceAttrSet("vault_token.test", "encrypted_client_token"),
				),
			},
		},
	})
}

func testResourceTokenConfig_pgp() string {
	return `
resource "vault_policy" "test" {
	name   = "test"
	policy = <<EOT
path "secret/*" { capabilities = [ "list" ] }
EOT
}

resource "vault_token" "test" {
	ttl      = "60s"
	policies = [ "${vault_policy.test.name}" ]
	pgp_key  = "keybase:terraformacctest"
}`
}

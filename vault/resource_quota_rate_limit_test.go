package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func randomQuotaRateString() string {
	whole := float64(acctest.RandIntRange(1000, 2000))
	decimal := float64(acctest.RandIntRange(0, 100)) / 100

	rateLimit := fmt.Sprintf("%.1f", whole+decimal)
	// Vault returns floats with trailing zeros trimmed
	return strings.TrimRight(strings.TrimRight(rateLimit, "0"), ".")
}

func TestQuotaRateLimit(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	rateLimit := randomQuotaRateString()
	newRateLimit := randomQuotaRateString()
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testQuotaRateLimitCheckDestroy([]string{rateLimit, newRateLimit}),
		Steps: []resource.TestStep{
			{
				Config: testQuotaRateLimit_Config(name, "", rateLimit, "1s", "0"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", rateLimit),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "interval", "1"),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "block_interval", "0"),
				),
			},
			{
				Config: testQuotaRateLimit_Config(name, "", newRateLimit, "60s", "120s"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", newRateLimit),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "interval", "60"),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "block_interval", "120"),
				),
			},
			{
				Config: testQuotaRateLimit_Config(name, "sys/", newRateLimit, "120", "60"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", "sys/"),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", newRateLimit),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "interval", "120"),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "block_interval", "60"),
				),
			},
		},
	})
}

func testQuotaRateLimitCheckDestroy(rateLimits []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*api.Client)

		for _, name := range rateLimits {
			resp, err := client.Logical().Read(quotaRateLimitPath(name))

			if err != nil {
				return err
			}

			if resp != nil {
				return fmt.Errorf("Resource Quota Rate Limit %s still exists", name)
			}
		}

		return nil
	}
}

// Caution: Don't set test rate values too low or other tests running concurrently might fail
func testQuotaRateLimit_Config(name, path, rate, interval, blockInterval string) string {
	return fmt.Sprintf(`
resource "vault_quota_rate_limit" "foobar" {
  name = "%s"
  path = "%s"
  rate = %s
  interval = "%s"
  block_interval = "%s"
}
`, name, path, rate, interval, blockInterval)
}

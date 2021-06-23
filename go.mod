module github.com/hashicorp/terraform-provider-vault

// This should ensure existing PRs are still valid
replace github.com/terraform-providers/terraform-provider-vault => ./

go 1.16

require (
	github.com/Azure/azure-sdk-for-go v29.0.0+incompatible
	github.com/Azure/go-autorest v11.7.1+incompatible
	github.com/aws/aws-sdk-go v1.30.27
	github.com/go-sql-driver/mysql v1.5.0
	github.com/gosimple/slug v1.4.1
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/go-multierror v1.1.0
	github.com/hashicorp/go-retryablehttp v0.6.8 // indirect
	github.com/hashicorp/terraform-plugin-sdk v1.9.0
	github.com/hashicorp/vault v1.2.0
	github.com/hashicorp/vault/api v1.0.5-0.20200519221902-385fac77e20f
	github.com/hashicorp/vault/sdk v0.1.14-0.20210526173046-412db2245e81
	github.com/mitchellh/go-homedir v1.1.0
	github.com/rainycape/unidecode v0.0.0-20150907023854-cb7f23ec59be // indirect
)

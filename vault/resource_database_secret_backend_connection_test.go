package vault

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
)

func TestAccDatabaseSecretBackendConnection_import(t *testing.T) {
	connURL := os.Getenv("POSTGRES_URL")
	if connURL == "" {
		t.Skip("POSTGRES_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_connection_lifetime", "0"),
				),
			},
			{
				ResourceName:            "vault_database_secret_backend_connection.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify_connection", "postgresql.0.connection_url"},
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_cassandra(t *testing.T) {
	host := os.Getenv("CASSANDRA_HOST")
	if host == "" {
		t.Skip("CASSANDRA_HOST not set")
	}

	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_cassandra(name, backend, host, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.hosts.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.hosts.0", host),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.port", "9042"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.username", username),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.password", password),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.tls", "false"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.insecure_tls", "false"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.pem_bundle", ""),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.pem_json", ""),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.protocol_version", "4"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.connect_timeout", "5"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_cassandraProtocol(t *testing.T) {
	host := os.Getenv("CASSANDRA_HOST")
	if host == "" {
		t.Skip("CASSANDRA_HOST not set")
	}

	username := os.Getenv("CASSANDRA_USERNAME")
	password := os.Getenv("CASSANDRA_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_cassandraProtocol(name, backend, host, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.hosts.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.hosts.0", host),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.port", "9042"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.username", username),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.password", password),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.tls", "false"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.insecure_tls", "false"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.pem_bundle", ""),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.pem_json", ""),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.protocol_version", "5"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "cassandra.0.connect_timeout", "5"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mongodbatlas(t *testing.T) {
	public_key := os.Getenv("MONGODB_ATLAS_PUBLIC_KEY")
	if public_key == "" {
		t.Skip("MONGODB_ATLAS_PUBLIC_KEY not set")
	}

	private_key := os.Getenv("MONGODB_ATLAS_PRIVATE_KEY")
	project_id := os.Getenv("MONGODB_ATLAS_PROJECT_ID")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mongodbatlas(name, backend, public_key, private_key, project_id),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mongodbatlas.0.public_key", public_key),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mongodbatlas.0.private_key", private_key),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mongodbatlas.0.project_id", project_id),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mongodb(t *testing.T) {
	connURL := os.Getenv("MONGODB_URL")
	if connURL == "" {
		t.Skip("MONGODB_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mongodb(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mongodb.0.connection_url", connURL),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mssql(t *testing.T) {
	connURL := os.Getenv("MSSQL_URL")
	if connURL == "" {
		t.Skip("MSSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mssql(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mssql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mssql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mssql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mssql.0.max_connection_lifetime", "0"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_mysql(t *testing.T) {
	connURL := os.Getenv("MYSQL_URL")
	if connURL == "" {
		t.Skip("MYSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	password := acctest.RandomWithPrefix("password")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql(name, backend, connURL, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.%", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.password", password),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_rds(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_rds.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_rds.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_rds.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_rds.0.max_connection_lifetime", "0"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_aurora(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_aurora.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_aurora.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_aurora.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_aurora.0.max_connection_lifetime", "0"),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_mysql_legacy(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_legacy.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_legacy.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_legacy.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql_legacy.0.max_connection_lifetime", "0"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnectionUpdate_mysql(t *testing.T) {
	connURL := os.Getenv("MYSQL_URL")
	if connURL == "" {
		t.Skip("MYSQL_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	password := acctest.RandomWithPrefix("password")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, backend, connURL, password, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.%", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.password", password),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, backend, connURL, password, 10),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_connection_lifetime", "10"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.%", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.password", password),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnectionTemplatedUpdateExcludePassword_mysql(t *testing.T) {
	connURL := os.Getenv("MYSQL_CONNECTION_URL")
	if connURL == "" {
		t.Skip("MYSQL_CONNECTION_URL not set")
	}
	username := os.Getenv("MYSQL_CONNECTION_USERNAME")
	if username == "" {
		t.Skip("MYSQL_CONNECTION_USERNAME not set")
	}
	password := os.Getenv("MYSQL_CONNECTION_PASSWORD")
	if password == "" {
		t.Skip("MYSQL_CONNECTION_PASSWORD not set")
	}

	// The MYQSL_CONNECTION_* vars are from within the test suite (might be different host due to docker)
	// They are used to create test DB users
	// MYSQL_TEMPLATED_URL is the template URL to be used in vault
	testConnURL := os.Getenv("MYSQL_TEMPLATED_URL")
	if testConnURL == "" {
		testConnURL = connURL
	}

	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	testUsername := acctest.RandomWithPrefix("username")
	testPassword := acctest.RandomWithPrefix("password")

	db := newMySQLConnection(t, connURL, username, password)
	createMySQSUser(t, db, testUsername, testPassword)
	defer deleteMySQLUser(t, db, testUsername)

	client := testProvider.Meta().(*api.Client)

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfigTemplated_mysql(name, backend, testConnURL, testUsername, testPassword, 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.connection_url", testConnURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_connection_lifetime", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.%", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.username", testUsername),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.password", testPassword),
				),
			},
			{
				Config: testAccDatabaseSecretBackendConnectionConfigTemplated_mysql(name, backend, testConnURL, testUsername, testPassword, 10),
				PreConfig: func() {
					path := fmt.Sprintf("%s/rotate-root/%s", backend, name)
					resp, err := client.Logical().Write(path, map[string]interface{}{})
					if err != nil {
						t.Error(err)
					}

					log.Printf("rotate-root: %v", resp)
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.connection_url", testConnURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "mysql.0.max_connection_lifetime", "10"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.%", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.username", testUsername),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "data.password", testPassword),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_postgresql(t *testing.T) {
	connURL := os.Getenv("POSTGRES_URL")
	if connURL == "" {
		t.Skip("POSTGRES_URL not set")
	}
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_postgresql(name, backend, connURL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.#", "1"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "root_rotation_statements.0", "FOOBAR"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.connection_url", connURL),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_open_connections", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_idle_connections", "0"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "postgresql.0.max_connection_lifetime", "0"),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_elasticsearch(t *testing.T) {
	connURL := os.Getenv("ELASTIC_URL")
	if connURL == "" {
		t.Skip("ELASTIC_URL not set")
	}

	username := os.Getenv("ELASTIC_USERNAME")
	password := os.Getenv("ELASTIC_PASSWORD")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDatabaseSecretBackendConnectionConfig_elasticsearch(name, backend, connURL, username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "elasticsearch.0.url", connURL),
				),
			},
		},
	})
}

func TestAccDatabaseSecretBackendConnection_snowflake(t *testing.T) {
	host := os.Getenv("SNOWFLAKE_HOST")
	port := os.Getenv("SNOWFLAKE_PORT")
	account := os.Getenv("SNOWFLAKE_ACCOUNT")
	username := os.Getenv("SNOWFLAKE_USERNAME")
	password := os.Getenv("SNOWFLAKE_PASSWORD")
	db := os.Getenv("SNOWFLAKE_DB")
	schema := os.Getenv("SNOWFLAKE_SCHEMA")
	warehouse := os.Getenv("SNOWFLAKE_WAREHOUSE")
	backend := acctest.RandomWithPrefix("tf-test-db")
	name := acctest.RandomWithPrefix("db")

	config := testAccDatabaseSecretBackendConnectionConfig_snowflake(name, backend, account, host, port, username, password, db, schema, warehouse)
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testAccDatabaseSecretBackendConnectionCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "name", name),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "backend", backend),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.#", "2"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.0", "dev"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "allowed_roles.1", "prod"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "verify_connection", "true"),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.account", account),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.host", host),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.port", port),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.username", username),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.password", password),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.database", db),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.schema", schema),
					resource.TestCheckResourceAttr("vault_database_secret_backend_connection.test", "snowflake.0.warehouse", warehouse),
				),
			},
		},
	})
	fmt.Println("hellow")
}

func testAccDatabaseSecretBackendConnectionCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_database_secret_backend_connection" {
			continue
		}
		secret, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if secret != nil {
			return fmt.Errorf("connection %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccDatabaseSecretBackendConnectionConfig_cassandra(name, path, host, username, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  cassandra {
    hosts = ["%s"]
    username = "%s"
    password = "%s"
    tls = false
  }
}
`, path, name, host, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_cassandraProtocol(name, path, host, username, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  cassandra {
    hosts = ["%s"]
    username = "%s"
    password = "%s"
    tls = false
    protocol_version = 5
  }
}
`, path, name, host, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_elasticsearch(name, path, host, username, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  elasticsearch {
    url = "%s"
    username = "%s"
    password = "%s"
  }
}
`, path, name, host, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mongodbatlas(name, path, public_key, private_key, project_id string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mongodbatlas {
    public_key  = "%s"
    private_key = "%s"
    project_id  = "%s"
  }
}
`, path, name, public_key, private_key, project_id)
}

func testAccDatabaseSecretBackendConnectionConfig_mongodb(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mongodb {
    connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_mssql(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mssql {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql(name, path, connURL, password string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql {
	  connection_url = "%s"
  }

  data = {
	  password = "%s"
  }
}
`, path, name, connURL, password)
}

func testAccDatabaseSecretBackendConnectionConfigUpdate_mysql(name, path, connURL, password string, connLifetime int) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql {
	  connection_url = "%s"
	  max_connection_lifetime = "%d"
  }

  data = {
	  password = "%s"
  }
}
`, path, name, connURL, connLifetime, password)
}

func testAccDatabaseSecretBackendConnectionConfigTemplated_mysql(name, path, connURL, username, password string, connLifetime int) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]

  mysql {
	  connection_url          = "%s"
	  max_connection_lifetime = "%d"
  }

  data = {
	  username = "%s"
	  password = "%s"
  }
}
`, path, name, connURL, connLifetime, username, password)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_rds(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql_rds {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_aurora(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql_aurora {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_mysql_legacy(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  mysql_legacy {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_postgresql(name, path, connURL string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  postgresql {
	  connection_url = "%s"
  }
}
`, path, name, connURL)
}

func testAccDatabaseSecretBackendConnectionConfig_snowflake(name, path, account, host, port, username, password, db, schema, warehouse string) string {
	return fmt.Sprintf(`
resource "vault_mount" "db" {
  path = "%s"
  type = "database"
}

resource "vault_database_secret_backend_connection" "test" {
  backend = "${vault_mount.db.path}"
  name = "%s"
  allowed_roles = ["dev", "prod"]
  root_rotation_statements = ["FOOBAR"]

  snowflake { 
    account = "%s"
	host = "%s"
	port = "%s"
	username = "%s"
	password = "%s"
	database = "%s"
	schema = "%s"
	warehouse = "%s"
  }
}
`, path, name, account, host, port, username, password, db, schema, warehouse)
}

func newMySQLConnection(t *testing.T, connURL string, username string, password string) *sql.DB {
	dbURL := dbutil.QueryHelper(connURL, map[string]string{
		"username": username,
		"password": password,
	})

	db, err := sql.Open("mysql", dbURL)
	if err != nil {
		t.Fatal(err)
	}

	return db
}

func createMySQSUser(t *testing.T, db *sql.DB, username string, password string) {
	createUser := fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED BY '%s';", username, password)
	grantPrivileges := fmt.Sprintf("GRANT ALL PRIVILEGES ON *.* TO '%s'@'%%' WITH GRANT OPTION;", username)

	_, err := db.Exec(createUser)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(grantPrivileges)
	if err != nil {
		t.Fatal(err)
	}
}

func deleteMySQLUser(t *testing.T, db *sql.DB, username string) {
	query := fmt.Sprintf("DROP USER '%s'@'%%';", username)
	_, err := db.Exec(query)
	if err != nil {
		t.Error(err)
	}
}

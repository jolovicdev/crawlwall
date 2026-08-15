package ledger

import (
	"database/sql"
	"embed"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed schema/*.sql
var schemaFS embed.FS

// dialect carries everything that differs between the supported databases.
// There is no ORM here on purpose: the ledger is one table with one insert and
// three queries, so a query builder would add a large dependency, reflection on
// the write path, and another layer to debug, in exchange for nothing this
// package needs. database/sql already is the portability layer; the differences
// that actually matter are collected below.
type dialect struct {
	name string

	// driver is the database/sql driver name to open.
	driver string

	// dsn is the driver-specific connection string.
	dsn string

	// schemaFile is the DDL applied at open, split and executed statement by
	// statement because neither pgx nor go-sql-driver accepts multi-statement
	// Exec by default.
	schemaFile string

	// numberedParams selects $1-style placeholders over ?.
	numberedParams bool

	// timestampsAsText keeps ts stored as RFC3339 text. SQLite has no native
	// timestamp type and existing crawlwall.db files already hold text, so it
	// stays text there and uses the native column type everywhere else.
	timestampsAsText bool

	// boolOr aggregates a boolean column. PostgreSQL has no MAX(boolean).
	boolOr string

	maxOpenConns int
}

// openDialect maps a ledger DSN onto a driver and connection string.
func openDialect(dsn string) (dialect, error) {
	scheme, rest, found := strings.Cut(dsn, "://")
	if !found {
		return dialect{}, fmt.Errorf("ledger DSN %q must start with a scheme such as sqlite://", dsn)
	}

	switch scheme {
	case "sqlite", "sqlite3":
		if strings.TrimSpace(rest) == "" {
			return dialect{}, fmt.Errorf("sqlite ledger path is required")
		}
		return dialect{
			name:             "sqlite",
			driver:           "sqlite",
			dsn:              sqliteConnString(rest),
			schemaFile:       "schema/sqlite.sql",
			timestampsAsText: true,
			boolOr:           "MAX(bot_verified)",
			// Writes already funnel through the async ledger's single
			// goroutine, so the pool only serves concurrent readers, which WAL
			// supports. A cap of 1 would make an export block every write.
			maxOpenConns: 4,
		}, nil

	case "postgres", "postgresql":
		return dialect{
			name:           "postgres",
			driver:         "pgx",
			dsn:            dsn,
			schemaFile:     "schema/postgres.sql",
			numberedParams: true,
			boolOr:         "bool_or(bot_verified)",
			maxOpenConns:   8,
		}, nil

	case "mysql", "mariadb":
		converted, err := mysqlConnString(dsn)
		if err != nil {
			return dialect{}, err
		}
		return dialect{
			name:         "mysql",
			driver:       "mysql",
			dsn:          converted,
			schemaFile:   "schema/mysql.sql",
			boolOr:       "MAX(bot_verified)",
			maxOpenConns: 8,
		}, nil

	default:
		return dialect{}, fmt.Errorf("unsupported ledger DSN scheme %q; use sqlite://, postgres://, or mysql://", scheme)
	}
}

// rebind rewrites ? placeholders into the dialect's form. Queries are written
// once with ? so there is a single copy of each statement.
func (d dialect) rebind(query string) string {
	if !d.numberedParams {
		return query
	}

	var out strings.Builder
	out.Grow(len(query) + 16)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] != '?' {
			out.WriteByte(query[i])
			continue
		}
		n++
		out.WriteByte('$')
		out.WriteString(strconv.Itoa(n))
	}
	return out.String()
}

// timeArg renders a timestamp for binding, in UTC so text and native columns
// sort and compare identically.
func (d dialect) timeArg(value time.Time) any {
	if d.timestampsAsText {
		return value.UTC().Format(time.RFC3339)
	}
	return value.UTC()
}

func (d dialect) applySchema(db *sql.DB) error {
	statements, err := schemaFS.ReadFile(d.schemaFile)
	if err != nil {
		return err
	}

	for _, statement := range splitStatements(string(statements)) {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("apply %s: %w", d.schemaFile, err)
		}
	}
	return nil
}

// splitStatements breaks DDL into individual statements. The schema files are
// ours and contain no semicolons inside literals, so splitting on ; is enough.
func splitStatements(schema string) []string {
	parts := strings.Split(schema, ";")
	statements := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			statements = append(statements, trimmed)
		}
	}
	return statements
}

// sqliteConnString adds per-connection pragmas. WAL plus a busy timeout lets
// writers wait briefly for the lock instead of dropping events with SQLITE_BUSY
// under concurrency.
func sqliteConnString(path string) string {
	pragmas := []string{
		"_pragma=busy_timeout(5000)",
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=foreign_keys(ON)",
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + strings.Join(pragmas, "&")
}

// mysqlConnString converts a mysql:// URL into the go-sql-driver DSN form,
// which is not a URL. Accepting the URL keeps every backend configured the same
// way in the Caddyfile.
func mysqlConnString(dsn string) (string, error) {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("parse mysql DSN: %w", err)
	}

	database := strings.TrimPrefix(parsed.Path, "/")
	if database == "" {
		return "", fmt.Errorf("mysql ledger DSN requires a database name")
	}

	// The go-sql-driver DSN is not a URL: user and password are taken
	// literally, with no percent-decoding. Re-encoding them via User.String()
	// would send a password like p@ss to the server as p%40ss.
	credentials := ""
	if parsed.User != nil {
		credentials = parsed.User.Username()
		if password, ok := parsed.User.Password(); ok {
			credentials += ":" + password
		}
		credentials += "@"
	}

	host := parsed.Host
	if host == "" {
		host = "127.0.0.1:3306"
	} else if parsed.Port() == "" {
		host += ":3306"
	}

	query := parsed.Query()
	// parseTime lets the driver hand back time.Time for DATETIME columns, and
	// utf8mb4 keeps user agents with non-ASCII bytes intact.
	if !query.Has("parseTime") {
		query.Set("parseTime", "true")
	}
	if !query.Has("charset") && !query.Has("collation") {
		query.Set("charset", "utf8mb4")
	}

	return fmt.Sprintf("%stcp(%s)/%s?%s", credentials, host, database, query.Encode()), nil
}

// parseTimestamp normalizes the ts column across drivers: native timestamp
// types come back as time.Time, SQLite's text column as string or []byte.
func parseTimestamp(value any) (time.Time, error) {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC(), nil
	case string:
		return time.Parse(time.RFC3339, typed)
	case []byte:
		return time.Parse(time.RFC3339, string(typed))
	case nil:
		return time.Time{}, fmt.Errorf("ts is null")
	default:
		return time.Time{}, fmt.Errorf("unsupported ts type %T", value)
	}
}

// asInt64 normalizes an aggregate result. SUM() is bigint on PostgreSQL and
// SQLite but DECIMAL on MySQL, which arrives as bytes.
func asInt64(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case float64:
		return int64(typed), nil
	case []byte:
		return parseInt64(string(typed))
	case string:
		return parseInt64(typed)
	case bool:
		if typed {
			return 1, nil
		}
		return 0, nil
	case nil:
		return 0, nil
	default:
		return 0, fmt.Errorf("unsupported numeric type %T", value)
	}
}

// parseInt64 accepts both integer and decimal renderings, since a DECIMAL
// aggregate may carry a fractional part depending on the column it ran over.
func parseInt64(value string) (int64, error) {
	if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
		return parsed, nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	return int64(parsed), nil
}

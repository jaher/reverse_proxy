package main

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	db       *sql.DB
	mu       sync.Mutex
	enabled  bool
	filepath string
}

func OpenDB(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// WAL mode for better concurrent read/write performance
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	if err := createSchema(sqlDB); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return &DB{
		db:       sqlDB,
		enabled:  true,
		filepath: path,
	}, nil
}

func createSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS connections (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			proxy_id        INTEGER NOT NULL,
			target          TEXT NOT NULL,
			client_addr     TEXT NOT NULL,
			start_time      DATETIME NOT NULL,
			end_time        DATETIME,
			status          TEXT NOT NULL,
			tls_intercepted BOOLEAN NOT NULL DEFAULT 0,
			request_data    BLOB,
			response_data   BLOB
		);

		CREATE INDEX IF NOT EXISTS idx_connections_target ON connections(target);
		CREATE INDEX IF NOT EXISTS idx_connections_start_time ON connections(start_time);
	`)
	return err
}

func (d *DB) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

func (d *DB) IsEnabled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enabled
}

func (d *DB) SetEnabled(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enabled = enabled
}

func (d *DB) Toggle() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enabled = !d.enabled
	return d.enabled
}

// SaveConnection writes a completed connection to the database.
func (d *DB) SaveConnection(conn *Connection) error {
	d.mu.Lock()
	enabled := d.enabled
	d.mu.Unlock()

	if !enabled {
		return nil
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	var reqData, respData []byte
	if conn.ClientToServer.Len() > 0 {
		reqData = make([]byte, conn.ClientToServer.Len())
		copy(reqData, conn.ClientToServer.Bytes())
	}
	if conn.ServerToClient.Len() > 0 {
		respData = make([]byte, conn.ServerToClient.Len())
		copy(respData, conn.ServerToClient.Bytes())
	}

	_, err := d.db.Exec(`
		INSERT INTO connections (proxy_id, target, client_addr, start_time, end_time, status, tls_intercepted, request_data, response_data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		conn.ID,
		conn.Target,
		conn.ClientAddr,
		conn.StartTime.UTC().Format(time.RFC3339),
		time.Now().UTC().Format(time.RFC3339),
		conn.Status,
		conn.TLSIntercepted,
		reqData,
		respData,
	)
	return err
}

// SaveAllConnections saves all connections from the store that are closed or failed.
func (d *DB) SaveAllConnections(store *ConnectionStore) (int, error) {
	conns := store.All()
	saved := 0
	for _, c := range conns {
		c.mu.Lock()
		status := c.Status
		c.mu.Unlock()
		if status == "CLOSED" || status == "FAILED" {
			if err := d.SaveConnection(c); err != nil {
				return saved, err
			}
			saved++
		}
	}
	return saved, nil
}

// LoadConnectionPayload loads the request and response data for a connection from the database.
// Returns (requestData, responseData, found, error).
func (d *DB) LoadConnectionPayload(proxyID int) ([]byte, []byte, bool, error) {
	row := d.db.QueryRow(
		`SELECT request_data, response_data FROM connections WHERE proxy_id = ? ORDER BY id DESC LIMIT 1`,
		proxyID,
	)

	var reqData, respData []byte
	err := row.Scan(&reqData, &respData)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}
	return reqData, respData, true, nil
}

func (d *DB) Path() string {
	return d.filepath
}

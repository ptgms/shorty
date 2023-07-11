package helpers

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

func CreateDBIfNotExists(db *sql.DB) {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS shorty_links (id SERIAL PRIMARY KEY, url TEXT NOT NULL, short_code TEXT NOT NULL UNIQUE, clicks INT NOT NULL DEFAULT 0, created_at TIMESTAMP NOT NULL DEFAULT NOW(), expires_at TEXT);")
	if err != nil {
		println("Error while trying to create table!")
		panic(err)
	}
}

func AddLink(db *sql.DB, url string, shortCode string, expiresAt string) {
	_, err := db.Exec("INSERT INTO shorty_links (url, short_code, expires_at) VALUES ($1, $2, $3)", url, shortCode, expiresAt)
	if err != nil {
		println("Error while trying to insert data!")
		println(err.Error())
	}
}

func RegisterClick(db *sql.DB, shortCode string) {
	_, err := db.Exec("UPDATE shorty_links SET clicks = clicks + 1 WHERE short_code = $1", shortCode)
	if err != nil {
		println("Error while trying to insert data!")
		println(err.Error())
	}
}

func GetLink(db *sql.DB, shortCode string) string {
	var url string
	var expiresAt string
	var timeNow = time.Now()
	err := db.QueryRow("SELECT url, expires_at FROM shorty_links WHERE short_code = $1", shortCode).Scan(&url, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ""
		}
		println("Error while trying to get data!")
		println(err.Error())
	}
	if expiresAt != "" {
		var expiresAtTime, _ = time.Parse("2006-01-02", expiresAt)
		if expiresAtTime.Before(timeNow) {
			RemoveLink(db, shortCode)
			return ""
		}
	}
	return url
}

func RemoveLink(db *sql.DB, shortCode string) {
	_, err := db.Exec("DELETE FROM shorty_links WHERE short_code = $1", shortCode)
	if err != nil {
		println("Error while trying to delete data!")
		println(err.Error())
	}
}

func GetLinks(db *sql.DB, path string) []PageTable {
	var links []PageTable
	rows, err := db.Query("SELECT short_code, url, clicks, created_at, expires_at FROM shorty_links ORDER BY clicks DESC")
	if err != nil {
		println("Error while trying to get data!")
		println(err.Error())
	}
	defer rows.Close()
	for rows.Next() {
		var link PageTable
		err := rows.Scan(&link.ShortLink, &link.Link, &link.Clicks, &link.AddedOn, &link.ExpiresAt)
		if err != nil {
			println("Error while trying to get data!")
			println(err.Error())
		}
		link.ShortLinkFull = path + "/" + link.ShortLink
		link.AddedOn = strings.Split(link.AddedOn, "T")[0]
		link.ExpiresAt = strings.Split(link.ExpiresAt, "T")[0]
		links = append(links, link)
	}
	return links
}

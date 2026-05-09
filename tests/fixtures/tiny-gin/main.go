// Tiny Gin app with a deliberate CWE-89 SQL injection.
//
// Used as a fixture for ai-codescan's Go pipeline; the handler concatenates
// a request parameter directly into a SQL string, which CodeQL/Semgrep/Joern
// should all flag.
package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	r := gin.Default()
	r.GET("/u", func(c *gin.Context) {
		userID := c.Query("id")
		// CWE-89: userID flows unparameterised into the SQL string.
		query := "SELECT id, name FROM users WHERE id=" + userID
		rows, err := db.Query(query)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()
		c.JSON(http.StatusOK, gin.H{"query": query})
	})
	r.Run(":3000")
}

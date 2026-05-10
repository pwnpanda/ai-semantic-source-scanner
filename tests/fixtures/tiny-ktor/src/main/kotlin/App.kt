// Tiny Ktor app with a deliberate CWE-89 SQL injection.
//
// Used as a fixture for ai-codescan's Kotlin pipeline; the handler
// concatenates a request parameter directly into a SQL string, which
// CodeQL's java-kotlin extractor + Semgrep should both flag.

package example

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import java.sql.DriverManager

fun main() {
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    embeddedServer(Netty, port = 3000) {
        routing {
            get("/u") {
                val userId = call.parameters["id"] ?: ""
                // CWE-89: userId flows unparameterised into the SQL string.
                val sql = "SELECT id, name FROM users WHERE id=$userId"
                val rs = conn.createStatement().executeQuery(sql)
                val rows = mutableListOf<String>()
                while (rs.next()) {
                    rows.add(rs.getString("name"))
                }
                call.respondText(rows.joinToString(","))
            }
        }
    }.start(wait = true)
}

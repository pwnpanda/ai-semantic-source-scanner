package example;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Minimal Spring controller with a deliberate CWE-89 SQLi.
 * The handler concatenates a request parameter directly into a SQL string,
 * which CodeQL/Semgrep/Joern should all flag.
 */
@RestController
public class UserController {

    @Autowired
    private DataSource dataSource;

    @GetMapping("/u")
    public List<String> getUser(@RequestParam("id") String userId) throws Exception {
        // CWE-89: userId flows unparameterised into the SQL string.
        String sql = "SELECT id, name FROM users WHERE id=" + userId;
        List<String> rows = new ArrayList<>();
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                rows.add(rs.getString("name"));
            }
        }
        return rows;
    }
}

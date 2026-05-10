// Tiny ASP.NET Core minimal-API app with a deliberate CWE-89 SQL injection.
//
// Used as a fixture for ai-codescan's C# pipeline; the handler concatenates
// a request parameter directly into a SQL string, which CodeQL/Semgrep
// should both flag.

using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

using var connection = new SqliteConnection("Data Source=:memory:");
connection.Open();

app.MapGet("/u", (string id) =>
{
    // CWE-89: ``id`` flows unparameterised into the SQL string.
    var sql = "SELECT id, name FROM users WHERE id=" + id;
    using var cmd = new SqliteCommand(sql, connection);
    using var reader = cmd.ExecuteReader();
    var rows = new List<string>();
    while (reader.Read())
    {
        rows.Add(reader.GetString(1));
    }
    return Results.Ok(rows);
});

app.Run();

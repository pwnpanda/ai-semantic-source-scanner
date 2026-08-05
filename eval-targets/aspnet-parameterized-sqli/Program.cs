// Safe ASP.NET Core minimal API target for SQLi negative evaluation.
//
// Ground truth:
// - No CWE-89 finding expected.
// - The route parameter `id` is bound through a SqliteCommand parameter.

using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

using var connection = new SqliteConnection("Data Source=:memory:");
connection.Open();

app.MapGet("/users/{id}", (string id) =>
{
    const string sql = "SELECT id, name FROM users WHERE id = @id";
    using var cmd = new SqliteCommand(sql, connection);
    cmd.Parameters.AddWithValue("@id", id);
    using var reader = cmd.ExecuteReader();

    var rows = new List<string>();
    while (reader.Read())
    {
        rows.Add(reader.GetString(1));
    }

    return Results.Ok(rows);
});

app.Run();

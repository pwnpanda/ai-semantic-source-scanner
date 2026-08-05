// Deliberately vulnerable ASP.NET Core minimal API target for scanner evaluation.
//
// Ground truth:
// - CWE-89 SQL injection at /users/{id}
// - The route parameter `id` is request-controlled by ASP.NET Core model binding.
// - `id` is concatenated into SQL and executed through SqliteCommand.ExecuteReader().

using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

using var connection = new SqliteConnection("Data Source=:memory:");
connection.Open();

app.MapGet("/users/{id}", (string id) =>
{
    var sql = "SELECT id, name FROM users WHERE id = " + id;
    using var cmd = new SqliteCommand(sql, connection);
    using var reader = cmd.ExecuteReader();

    var rows = new List<string>();
    while (reader.Read())
    {
        rows.Add(reader.GetString(1));
    }

    return Results.Ok(rows);
});

app.MapGet("/health", () => Results.Ok("ok"));

app.Run();

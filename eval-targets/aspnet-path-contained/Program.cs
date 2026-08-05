// Safe ASP.NET Core minimal API target for path traversal negative evaluation.
//
// Ground truth:
// - No CWE-22 finding expected.
// - The requested file name is canonicalized and checked against a fixed root.

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "public"));
var rootWithSeparator = root.EndsWith(Path.DirectorySeparatorChar)
    ? root
    : root + Path.DirectorySeparatorChar;

app.MapGet("/files/{name}", (string name) =>
{
    var requested = Path.GetFullPath(Path.Combine(root, name));
    if (!requested.StartsWith(rootWithSeparator, StringComparison.Ordinal))
    {
        return Results.BadRequest();
    }

    return Results.Text(File.ReadAllText(requested));
});

app.Run();

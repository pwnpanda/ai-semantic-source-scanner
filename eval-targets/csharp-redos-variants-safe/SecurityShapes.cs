using System.Text.RegularExpressions;

public static class SecurityShapes
{
    private static readonly Regex Identifier = new("^[a-z0-9_-]{1,64}$");

    public static bool Match(string input)
    {
        return Identifier.IsMatch(input) || Regex.IsMatch(input, "^[a-z0-9_-]{1,64}$");
    }
}

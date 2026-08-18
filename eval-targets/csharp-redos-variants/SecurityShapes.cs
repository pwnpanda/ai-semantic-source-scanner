using System.Text.RegularExpressions;

public static class SecurityShapes
{
    public static bool Match(string input, string pattern)
    {
        var dynamicRegex = new Regex(pattern);
        return dynamicRegex.IsMatch(input) || Regex.IsMatch(input, pattern);
    }
}

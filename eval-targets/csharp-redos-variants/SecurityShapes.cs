using System.Text.RegularExpressions;
using System.Xml;

public static class SecurityShapes
{
    public static bool MatchDynamic(string input, string pattern)
    {
        var dynamicRegex = new Regex(pattern);
        return dynamicRegex.IsMatch(input);
    }

    public static bool MatchStatic(string pattern, string input)
    {
        return Regex.IsMatch(input, pattern);
    }

    public static XmlTextReader ReadXml(string xml)
    {
        return new XmlTextReader(xml);
    }
}

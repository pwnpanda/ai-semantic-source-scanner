package example;

import freemarker.template.Configuration;
import freemarker.template.Template;
import java.io.StringReader;
import java.io.Writer;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.xml.xpath.XPath;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
final class SecurityShapes {
  private final VelocityEngine velocity;
  private final Configuration freemarker;
  private final XPath xpath;
  private final DirContext directory;
  private final SearchControls controls;
  private final Writer writer;
  private final Object document;

  SecurityShapes(
      VelocityEngine velocity,
      Configuration freemarker,
      XPath xpath,
      DirContext directory,
      SearchControls controls,
      Writer writer,
      Object document) {
    this.velocity = velocity;
    this.freemarker = freemarker;
    this.xpath = xpath;
    this.directory = directory;
    this.controls = controls;
    this.writer = writer;
    this.document = document;
  }

  @PostMapping("/freemarker")
  void freemarker(@RequestBody String freemarkerSource) throws Exception {
    Template template =
        new Template(
            "dynamic", new StringReader("<p>" + freemarkerSource + "</p>"), freemarker);
    template.process(new Object(), writer);
  }

  @PostMapping("/velocity")
  void velocity(@RequestBody String velocitySource) {
    velocity.evaluate(
        new VelocityContext(), writer, "dynamic", "#set($x = 1)" + velocitySource);
  }

  @PostMapping("/xpath")
  void xpath(@RequestParam String xpathExpression) throws Exception {
    xpath.evaluate("/accounts/account[" + xpathExpression + "]", document);
  }

  @PostMapping("/ldap")
  void ldap(@RequestParam String ldapFilter) throws Exception {
    directory.search("ou=people", "(&(objectClass=person)" + ldapFilter + ")", controls);
  }
}

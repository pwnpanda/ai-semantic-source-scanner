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
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
final class SecurityShapes {
  private static final SimpleMailMessage FIXED_MESSAGE = new SimpleMailMessage();
  private static final String PAGE = "<p>${value}</p>";
  private static final String EXPRESSION = "/accounts/account[@active='true']";
  private static final String FILTER = "(objectClass=person)";

  private final VelocityEngine velocity;
  private final Configuration freemarker;
  private final XPath xpath;
  private final DirContext directory;
  private final SearchControls controls;
  private final Writer writer;
  private final Object document;
  private final JavaMailSender mailSender;
  private final MessageBus messageBus;

  SecurityShapes(
      VelocityEngine velocity,
      Configuration freemarker,
      XPath xpath,
      DirContext directory,
      SearchControls controls,
      Writer writer,
      Object document,
      JavaMailSender mailSender,
      MessageBus messageBus) {
    this.velocity = velocity;
    this.freemarker = freemarker;
    this.xpath = xpath;
    this.directory = directory;
    this.controls = controls;
    this.writer = writer;
    this.document = document;
    this.mailSender = mailSender;
    this.messageBus = messageBus;
  }

  @PostMapping("/inspect")
  void inspect(@RequestBody Object model) throws Exception {
    Template template = new Template("fixed", new StringReader(PAGE), freemarker);
    template.process(model, writer);
    VelocityContext context = new VelocityContext();
    context.put("value", model);
    velocity.evaluate(context, writer, "fixed", PAGE);
    xpath.evaluate(EXPRESSION, document);
    directory.search("ou=people", FILTER, controls);
    messageBus.send(model);
    mailSender.send(FIXED_MESSAGE);
  }

  @PostMapping("/select-sender")
  void selectSender(@RequestBody JavaMailSender selectedSender) {
    selectedSender.send(FIXED_MESSAGE);
  }

  interface MessageBus {
    void send(Object message);
  }
}

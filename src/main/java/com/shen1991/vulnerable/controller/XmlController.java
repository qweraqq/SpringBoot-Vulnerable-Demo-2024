package com.shen1991.vulnerable.controller;

import org.jdom2.Document;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.io.StringReader;

@Controller
public class XmlController {
    @RequestMapping(value = "/xml-vulnerable", method = RequestMethod.GET)
    public String xmlVulnerable(
            @RequestParam(name = "xml", required = false, defaultValue = "<test>a</test>") String xml,
            Model model) {

        SAXBuilder sax = new SAXBuilder();

        try {
            Document doc = sax.build(new StringReader(xml));
            model.addAttribute("name", doc.getRootElement().getValue());

        } catch (JDOMException | IOException e) {
            model.addAttribute("name", "xml parsing failed");
        }
        return "xml";

    }
}

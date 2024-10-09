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
            @RequestParam(name = "xml", required = false, defaultValue = "<test>World</test>") String xml,
            Model model) {

        SAXBuilder sax = new SAXBuilder();
        try {
            Document doc = sax.build(new StringReader(xml));
            model.addAttribute("name", doc.getRootElement().getValue());

        } catch (JDOMException | IOException e) {
            model.addAttribute("name", "failed: " + e.getMessage());
        }
        return "xml";

    }


    @RequestMapping(value = "/xml", method = RequestMethod.GET)
    public String xml(
            @RequestParam(name = "xml", required = false, defaultValue = "<test>World</test>") String xml,
            Model model) {

        // https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#saxbuilder
        SAXBuilder sax = new SAXBuilder();
        sax.setFeature("http://xml.org/sax/features/external-general-entities", false);
        sax.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        sax.setExpandEntities(false);
        try {
            Document doc = sax.build(new StringReader(xml));
            model.addAttribute("name", doc.getRootElement().getValue());

        } catch (JDOMException | IOException e) {
            model.addAttribute("name", "failed: " + e.getMessage());
        }
        return "xml";

    }
}

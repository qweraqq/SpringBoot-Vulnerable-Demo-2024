package com.shen1991.vulnerable.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;


@Controller
public class XssController {
    @RequestMapping(value = "/greeting-vulnerable", method = RequestMethod.GET)
    public String greetingVulnerable(@RequestParam(name = "name", required = false, defaultValue = "World") String name,
                                     Model model) {
        model.addAttribute("name", name);
        return "greeting-vulnerable";
    }

    @RequestMapping(value = "/greeting", method = RequestMethod.GET)
    public String greeting(@RequestParam(name = "name", required = false, defaultValue = "World") String name,
                           Model model) {
        model.addAttribute("name", name);
        return "greeting";
    }
}
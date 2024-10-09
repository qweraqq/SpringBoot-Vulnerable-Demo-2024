package com.shen1991.vulnerable.controller;

import ognl.Ognl;
import ognl.OgnlException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class CmdController {

    @RequestMapping(value = "/ongl-vulnerable", method = RequestMethod.GET)
    public String onglVulnerable(@RequestParam(name = "name", required = false, defaultValue = "World") String name,
                                 Model model) {
        String expression = "";
        try {
            expression = runOgnlVulnerable(name);
        } catch (OgnlException e) {
            model.addAttribute("error", e);
        }
        model.addAttribute("message", expression);
        return "ongl";
    }

    private String runOgnlVulnerable(String expression) throws OgnlException {
        Object root = new Object();
        Object res = Ognl.getValue(expression, root);

        return res.toString();
    }

    @RequestMapping(value = "/ongl", method = RequestMethod.GET)
    public String ongl(@RequestParam(name = "name", required = false, defaultValue = "World") String name,
                       Model model) {
        String expression = "";
        try {
            expression = runOgnl(name);
        } catch (OgnlException e) {
            model.addAttribute("error", e);
        }
        model.addAttribute("message", expression);
        return "ongl";
    }

    private String runOgnl(String expression) throws OgnlException {
        // https://codeql.github.com/codeql-query-help/java/java-ognl-injection/
        // GOOD: The name is validated and expression is evaluated in sandbox
        System.setProperty("ognl.security.manager", ""); // Or add -Dognl.security.manager to JVM args
        if (isValid(expression)) {
            Object root = new Object();
            Object res = Ognl.getValue(expression, root);
            return res.toString();
        } else {
            // Reject the request
            return "rejected";
        }

    }

    public boolean isValid(String expression) {
        // Custom method to validate the expression.
        // For instance, make sure it doesn't include unexpected code.
        return !expression.contains("exec");
    }

}

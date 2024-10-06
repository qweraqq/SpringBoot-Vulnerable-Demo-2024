package com.shen1991.vulnerable.controller;

import ognl.Ognl;
import ognl.OgnlContext;
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
            expression = runOgnl(name);
        } catch (OgnlException e) {
            model.addAttribute("error", e);
        }
        model.addAttribute("message", expression);
        return "ongl";
    }

    private String runOgnl(String expression) throws OgnlException {
        String newStr = '"' + expression + '"';
        OgnlContext ctx = new OgnlContext();
        Object expr = Ognl.parseExpression(newStr);
        Object root = new Object();
        Object res = Ognl.getValue(expr, ctx, root);

        return res.toString();
    }

}

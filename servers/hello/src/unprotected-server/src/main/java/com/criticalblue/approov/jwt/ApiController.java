package com.criticalblue.approov.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class ApiController {

    private static Logger logger = LoggerFactory.getLogger(ApiController.class);

    @GetMapping("/")
    public Map<String, Object> helloV1() {

        logger.info("Serving request for endpoint '/', that isn't protected by an Approov Token.");

        Map<String, Object> response = new LinkedHashMap<>();

        response.put("message", "Hello, World!");

        return response;
    }
}

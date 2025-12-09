package com.criticalblue.approov.jwt;

import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;
import java.util.Map;

@Component
public class CustomServletErrorAttributes extends DefaultErrorAttributes {

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {

        Map<String, Object> errorAttributes = super.getErrorAttributes(webRequest, options);

        // Remove from response in order to make the response comply with the Hello API specification
        errorAttributes.remove("timestamp");
        errorAttributes.remove("message");
        errorAttributes.remove("path");
        errorAttributes.remove("error");
        errorAttributes.remove("trace");
        errorAttributes.remove("status");

        return errorAttributes;
    }
}

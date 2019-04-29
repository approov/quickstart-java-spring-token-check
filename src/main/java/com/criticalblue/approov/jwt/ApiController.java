package com.criticalblue.approov.jwt;

import com.criticalblue.approov.jwt.authentication.ApproovAuthentication;
import com.criticalblue.approov.jwt.dto.ApiEndpoints;
import com.criticalblue.approov.jwt.dto.Forms;
import com.criticalblue.approov.jwt.dto.Hello;
import com.criticalblue.approov.jwt.dto.Shapes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;

@RestController
public class ApiController {

    private static Logger logger = LoggerFactory.getLogger(ApproovAuthentication.class);

    @GetMapping("/")
    public ApiEndpoints apiEndpoints() {

        logger.info("Serving request for endpoint '/', that is not protect by an Approov Token.");

        // This endpoint is not protected by an Approov token, thus the Approov Authentication does not take place, and
        // everything works as usual.

        return new ApiEndpoints();
    }

    @GetMapping("/hello")
    public Hello hello() {

        logger.info("Serving request for endpoint '/hello', that is not protect by an Approov Token.");

        // This endpoint is not protected by an Approov token, thus the Approov Authentication does not take place, and
        // everything works as usual.

        return new Hello();
    }

    @GetMapping("/shapes")
    public Shapes shapes() {

        logger.info("Serving request for endpoint '/shapes', that is protect by an Approov Token.");

        // This endpoint is protected by an Approov token that MUST be signed with the secret shared between Arppoov and
        // the API server, and an exception will be raised if the Approov token is not signed with it, or its
        // expiration of 5 minutes have been exceeded.
        //
        // The shared secret is the one declared in the .env file in the var `APPROOV_BASE64_SECRET`, and you retrieve
        // it from the Approov admin portal. For this demo purpose we will test the API with a tool like Postman, thus
        // we will generate them in our computer.
        //
        // The raised exception will be: com.criticalblue.approov.jwt.authentication.ApproovAuthenticationException.
        //
        // Throwing the ApproovAuthenticationException on an invalid Approov token is controlled by the environment
        // variable `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN`, that can be found int the .env file. Setting its value to
        // `false` should only be used when you want to limit the response returned to the client, instead of totally
        // blocking him, but once Approov uses a positive attestation model(no false positives), we discourage this
        // approach.

        return new Shapes();
    }

    @GetMapping("/forms")
    public Forms forms(HttpServletRequest request) {

        logger.info("Serving request for endpoint '/forms', that is protect by an Approov Token.");

        // This endpoint is protected by an Approov token, where in addition to what is checked in `/shapes` endpoint, a
        // check is also performed to see if contains a key named `pay` in the Approov token payload section. When the
        // value in this key does not match the request claim value, an exception will be raised, but you cannot catch
        // it here, once its thrown before reaching this method.
        //
        // The exception will be: com.criticalblue.approov.jwt.authentication.ApproovPayloadAuthenticationException.
        //
        // The value in the `pay` key is a base64 encoded hash(SHA256) of the Approov header claim value, like an
        // Authorization token. So the Approov header claim value is retrieved from an header that is configurable from
        // the .env file, by changing the default value `Authorization` in the var `APPROOV_CLAIM_HEADER_NAME`.
        //
        // Throwing the ApproovPayloadAuthenticationException on an invalid custom payload claim is controlled by the
        // environment variable `APPROOV_ABORT_REQUEST_ON_INVALID_CUSTOM_PAYLOAD_CLAIM`, that can be found int the .env
        // file. Setting its value to `false` should only be used when you want to limit the response returned to the
        // client, instead of totally blocking him, but once Approov uses a positive attestation model(no false
        // positives), we discourage this approach.

        return new Forms();
    }
}

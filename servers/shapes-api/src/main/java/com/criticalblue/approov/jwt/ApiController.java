package com.criticalblue.approov.jwt;

import com.criticalblue.approov.jwt.authentication.ApproovAuthentication;
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
    private RandomShape randomShape = new RandomShape();
    private RandomForm randomForm = new RandomForm();

    @GetMapping("/")
    public String homePage() {

        logger.info("Serving request for endpoint '/', that is not protect by an Approov Token.");

        // This endpoint is not protected by an Approov token, thus the Approov Authentication does not take place, and
        // everything works as usual.

        return "<!DOCTYPE html>\n" +
                "<html>\n" +
                "  <body>\n" +
                "    <h1>Approov Mobile App Authentication</h1>\n" +
                "    <p>\n" +
                "      To learn more about how Approov protects your APIs from malicious bots and tampered or fake apps, see <a href=\"https://approov.io/docs\">https://approov.io/docs</a>.\n" +
                "    </p>\n" +
                "  </body>\n" +
                "</html>";
    }

    @GetMapping("/v1/hello")
    public Hello helloV1() {

        logger.info("Serving request for endpoint '/v1/hello', that is not protect by an Approov Token.");

        return new Hello();
    }

    @GetMapping("/v1/shapes")
    public Shapes shapesV1() {

        logger.info("Serving request for endpoint '/v1/shapes', that is not protect by an Approov Token.");

        String shape = randomShape.create();
        return new Shapes(shape);
    }

    @GetMapping("/v1/forms")
    public Forms formsV1(HttpServletRequest request) {

        logger.info("Serving request for endpoint '/v1/forms', that is not protect by an Approov Token.");

        String form = randomForm.create();
        return new Forms(form);
    }

    @GetMapping("/v2/hello")
    public Hello helloV2() {

        logger.info("Serving request for endpoint '/v2/hello', that is not protect by an Approov Token.");

        // This endpoint is not protected by an Approov token, thus the Approov Authentication does not take place, and
        // everything works as usual.

        return new Hello();
    }

    @GetMapping("/v2/shapes")
    public Shapes shapesV2() {

        logger.info("Serving request for endpoint '/v2/shapes', that is protect by an Approov Token.");

        // This endpoint is protected by an Approov token that MUST be signed with the secret shared between Arppoov and
        // the API server, and an exception will be raised if the Approov token is not signed with it, or its
        // expiration of 5 minutes have been exceeded.
        //
        // The shared secret is the one declared in the .env file in the var `APPROOV_BASE64_SECRET`, and you retrieve
        // it with the Approov CLI tool. For this demo purpose we will test the API with a tool like Postman, thus
        // we can generate some Approov tokens with the help of the Approov CLI tool.
        //
        // The raised exception will be: com.criticalblue.approov.jwt.authentication.ApproovAuthenticationException.
        //
        // Throwing the ApproovAuthenticationException on an invalid Approov token is controlled by the environment
        // variable `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN`, that can be found in the .env file. Setting its value to
        // `false` should only be used when you want to limit the response returned to the client, instead of totally
        // blocking it, but once Approov uses a positive attestation model(no false positives), we discourage this
        // approach, unless in an initial phase where you just want to assert that everything works as you intend to.

        String shape = randomShape.create();
        return new Shapes(shape);
    }

    @GetMapping("/v2/forms")
    public Forms formsV2(HttpServletRequest request) {

        logger.info("Serving request for endpoint '/v2/forms', that is protect by an Approov Token.");

        // This endpoint is protected by an Approov token, where in addition to what is checked in `/shapes` endpoint, a
        // check is also performed to see if contains a key named `pay` in the Approov token payload section. When the
        // value in this key does not match the request claim value, an exception will be raised, but you cannot catch
        // it here, once its thrown before reaching this method.
        //
        // The exception will be: com.criticalblue.approov.jwt.authentication.ApproovTokenBindingAuthenticationException.
        //
        // The value in the `pay` key is a base64 encoded hash(SHA256) of the Approov header claim value, like an
        // Authorization token. So the Approov header claim value is retrieved from an header that is configurable from
        // the .env file, by changing the default value `Authorization` in the var `APPROOV_TOKEN_BINDING_HEADER_NAME`.
        //
        // Throwing the ApproovTokenBindingAuthenticationException on an invalid custom payload claim is controlled by the
        // environment variable `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN_BINDING`, that can be found int the .env
        // file. Setting its value to `false` should only be used when you want to limit the response returned to the
        // client, instead of totally blocking it, but once Approov uses a positive attestation model(no false
        // positives), we discourage this approach, unless in an initial phase where you just want to assert that
        // everything works as you intend to.

        String form = randomForm.create();
        return new Forms(form);
    }
}

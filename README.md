# Approov QuickStart - Java Spring Token Check

[Approov](https://approov.io) is an API security solution used to verify that requests received by your backend services originate from trusted versions of your mobile apps.

This repo implements the Approov server-side request verification code with the Java Spring framework in a simple Hello API server, which performs the verification check before allowing valid traffic to be processed by the API endpoint.

Originally this repo was just to show the Approov token integration example on a Java Spring API as described in the article: [Approov Integration in a Java Spring API](https://approov.io/blog//approov-integration-in-a-python-flask-api), that you can still find at [/servers/shapes-api](/servers/shapes-api).


## Approov Integration Quickstart

The quickstart was tested with the following Operating Systems:

* Ubuntu 20.04
* MacOS Big Sur
* Windows 10 WSL2 - Ubuntu 20.04

First, setup the [Approov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli).

Now, register the API domain for which Approov will issues tokens:

```bash
approov api -add api.example.com
```

Next, enable your Approov `admin` role with:

```bash
eval `approov role admin`
````

Now, get your Approov Secret with the [Approov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli):

```bash
approov secret -get base64
```

Next, add the [Approov secret](https://approov.io/docs/latest/approov-usage-documentation/#account-secret-key-export) to your project `.env` file:

```env
APPROOV_BASE64_SECRET=approov_base64_secret_here
```

Now, to check the Approov token you need to add the [jwtk/jjwt](https://github.com/jwtk/jjwt) package to your `build.gradle` dependencies:

```gradle
dependencies {

    // omitted..

    implementation group: 'io.jsonwebtoken', name: 'jjwt-api', version: '0.11.2'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.2',
        'io.jsonwebtoken:jjwt-jackson:0.11.2'
}
```

Next, add the package `com.criticalblue.approov.jwt.authentication` to your current project by copying (from this repo) the entire [authentication](/servers/hello/src/approov-protected-server/token-check/src/main/java/com/criticalblue/approov/jwt/authentication) folder into your project.


Now, use it from the class in your project that extends the `WebSecurityConfigurerAdapter`. For example:

```java
package com.yourcompany.projectname;

import com.criticalblue.approov.jwt.authentication.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static ApproovConfig approovConfig = ApproovConfig.getInstance();

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedMethods(Arrays.asList("GET"));
        configuration.addAllowedHeader("Authorization");
        configuration.addAllowedHeader("Approov-Token");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/error");
    }

    @Configuration
    // @IMPORTANT Approov token check must be at Order 1. Any other type of
    //            Authentication (User, API Key, etc.) for the request should go
    //            after with @Order(2)
    @Order(1)
    public static class ApproovWebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.cors();

            http
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                .csrf().disable()
                // @APPROOV The Approov Token check is triggered here.
                .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            http
                .securityContext()
                // @APPROOV The Approov Token check is configured here.
                .securityContextRepository(new ApproovSecurityContextRepository(approovConfig))
                .and()
                    .exceptionHandling()
                    // @APPROOV The Approov Token check is done here
                    .authenticationEntryPoint(new ApproovAuthenticationEntryPoint())
                .and()
                    // @APPROOV This matcher will require the Approov token for
                    // all API endpoints.
                    .antMatcher("/")
                        .authorizeRequests()
                        .antMatchers(HttpMethod.GET, "/**").authenticated();
        }
    }
}
```

> **NOTE:** When the Approov token validation fails we return a `401` with an empty body, because we don't want to give clues to an attacker about the reason the request failed, and you can go even further by returning a `400`.

Not enough details in the bare bones quickstart? No worries, check the [detailed quickstarts](QUICKSTARTS.md) that contain a more comprehensive set of instructions, including how to test the Approov integration.


## More Information

* [Approov Overview](OVERVIEW.md)
* [Detailed Quickstarts](QUICKSTARTS.md)
* [Examples](EXAMPLES.md)
* [Testing](TESTING.md)

### System Clock

In order to correctly check for the expiration times of the Approov tokens is very important that the backend server is synchronizing automatically the system clock over the network with an authoritative time source. In Linux this is usually done with a NTP server.


## Issues

If you find any issue while following our instructions then just report it [here](https://github.com/approov/quickstart-java-spring-token-check/issues), with the steps to reproduce it, and we will sort it out and/or guide you to the correct path.


## Useful Links

If you wish to explore the Approov solution in more depth, then why not try one of the following links as a jumping off point:

* [Approov Free Trial](https://approov.io/signup)(no credit card needed)
* [Approov QuickStarts](https://approov.io/docs/latest/approov-integration-examples/)
* [Approov Get Started](https://approov.io/product/demo)
* [Approov Docs](https://approov.io/docs)
* [Approov Blog](https://approov.io/blog/)
* [Approov Resources](https://approov.io/resource/)
* [Approov Customer Stories](https://approov.io/customer)
* [Approov Support](https://approov.io/contact)
* [About Us](https://approov.io/company)
* [Contact Us](https://approov.io/contact)

# APPROOV JAVA SPRING INTEGRATION EXAMPLE

To see how a Java Spring server runs with an Approov integration please follow the
[Approov Shapes API Server](./docs/approov-shapes-api-server.md) walk-through.

The implementation of the Approov token check is on [this folder](./src/main/java/com/criticalblue/approov/jwt/authentication), that uses the Java Spring Framework Security package to implement the authentication flow for checking the Approov token.

Now let's continue reading this README for a **quick start** introduction in how
to integrate Approov on a project built with the Java Spring Framework.

You may want to first follow [this demo walk-through](./docs/approov-shapes-api-server.md) before you try the Approov integration on your own app, but it's not mandatory you do it, but doing so will give you a better understanding how everything fits together in the simple Shapes app.


## APPROOV VALIDATION PROCESS

Before we dive into the code we need to understand the Approov validation
process on the back-end side.

### The Approov Token

API calls protected by Approov will typically include a header holding an Approov
JWT token. This token must be checked to ensure it has not expired and that it is
properly signed with the secret shared between the back-end and the Approov cloud
service.

We will use the `io.jsonwebtoken.*` package to help us in the validation of the
Approov JWT token.

> **NOTE**
>
> Just to be sure that we are on the same page, a JWT token have 3 parts, that
> are separated by dots and represented as a string in the format of
> `header.payload.signature`. Read more about JWT tokens [here](https://jwt.io/introduction/).

### The Approov Token Binding

When an Approov token contains the key `pay`, its value is a base64 encoded sha256 hash of
some unique identifier in the request, that we may want to bind with the Approov token, in order
to enhance the security on that request, like an Authorization token.

Dummy example for the JWT token middle part, the payload:

```
{
    "exp": 123456789, # required - the timestamp for when the token expires.
    "pay":"f3U2fniBJVE04Tdecj0d6orV9qT9t52TjfHxdUqDBgY=" # optional - a sha256 hash of the token binding value, encoded with base64.
}
```

The token binding in an Approov token is the one in the `pay` key:

```
"pay":"f3U2fniBJVE04Tdecj0d6orV9qT9t52TjfHxdUqDBgY="
```

**ALERT**:

Please bear in mind that the token binding is not meant to pass application data
to the API server.

## SYSTEM CLOCK

In order to correctly check for the expiration times of the Approov tokens is
important that the system clock for the Java server is synchronized
automatically over the network with an authoritative time source. In Linux this
is usual done with an NTP server.


## REQUIREMENTS

We will use Java `11.0.3` with the Spring Boot `2.1.3.RELEASE`, and Gradle
`5.2.1` to compile, build and run this demo.

Docker is only required for developers wanting to use the Java docker stack provided
by the [stack](./stack) bash script, that is a wrapper around docker commands.

Postman is the tool we recommend to be used when simulating the queries against
the API, but feel free to use any other tool of your preference.


## The Docker Stack

We recommend the use of the included Docker stack to play with this Approov
integration.

For details on how to use it you need to follow the setup instructions in the
[Approov Shapes API Server](./docs/approov-shapes-api-server.md#development-environment)
walk-through.

For example, to get a shell inside the docker stack:

```bash
$ ./stack shell
```

Now, you can do whatever you need inside this shell, like:

```bash
$ java --version
openjdk 11.0.3 2019-04-16
OpenJDK Runtime Environment (build 11.0.3+1-Debian-1bpo91)
OpenJDK 64-Bit Server VM (build 11.0.3+1-Debian-1bpo91, mixed mode, sharing)

$ gradle --version

------------------------------------------------------------
Gradle 5.2.1
------------------------------------------------------------

Build time:   2019-02-08 19:00:10 UTC
Revision:     f02764e074c32ee8851a4e1877dd1fea8ffb7183

Kotlin DSL:   1.1.3
Kotlin:       1.3.20
Groovy:       2.5.4
Ant:          Apache Ant(TM) version 1.9.13 compiled on July 10 2018
JVM:          11.0.3 (Oracle Corporation 11.0.3+1-Debian-1bpo91)
OS:           Linux 4.15.0-47-generic amd64
```

The use of the docker stack is not mandatory thus feel free to use your local environment to play with this Approov integration.

### The Postman Collection

As you go through your Approov Integration you may want to test it and if you are using Postman then you can import this [Postman collection](https://raw.githubusercontent.com/approov/postman-collections/master/quickstarts/shapes-api/shapes-api.postman_collection.json) to see how it's done for the Approov Shapes API Server [example](./docs/approov-shapes-api-server.md), and use it as an inspiration or starting point for your own collection.

The Approov tokens used in the headers of this Postman collection where generated with this [Python script](./bin/generate-token), that used the dummy secret set on the `.env.example` file to sign all the Approov tokens.

If you are using the Aproov secret retrieved with the [Approov CLI]((https://approov.io/docs/latest/approov-cli-tool-reference/)) tool then you need to use it to generate some valid and invalid tokens. Some examples of using it can be found in the Approov [docs](https://approov.io/docs/latest/approov-usage-documentation/#generating-example-tokens).


## DEPENDENCIES

Probably the only dependencies from the [build.gradle](./build.gradle) that you
do not have in your own project are this ones:

```gradle
implementation 'io.jsonwebtoken:jjwt-api:0.10.5'
runtime 'io.jsonwebtoken:jjwt-impl:0.10.5',
        'io.jsonwebtoken:jjwt-jackson:0.10.5'

implementation 'io.github.cdimascio:java-dotenv:5.0.1'
```

If they are not yet in your project add them and rebuild your project.


## HOW TO INTEGRATE APPROOV

We will learn how to integrate Approov in a skeleton generated with Spring Boot,
where we added 3 endpoints:

* `/` - Not protected with Approov.
* `/v2/hello` - Not protected with Approov.
* `/v2/shapes` - Approov protected.
* `/v2/forms` - Approov protected, and with a check for the Approov Approov token binding.

To integrate Approov in your own project you may want to use the package
[com.criticalblue.approov.jwt.authentication](./src/main/java/com/criticalblue/approov/jwt/authentication), that contains all the code that
is project agnostic. To use this package you need to configure it from the class
extending the `WebSecurityConfigurerAdapter`, that in this demo is named as
[WebSecurityConfig](./src/main/java/com/criticalblue/approov/jwt/WebSecurityConfig.java).


### Understanding the WebSecurityConfig

The [WebSecurityConfig](./src/main/java/com/criticalblue/approov/jwt/WebSecurityConfig.java)
is where we will setup the security configuration for the Spring framework, and
this is done by `@override` some of the methods for the abstract class it
extends from, the `WebSecurityConfigurerAdapter`.

When implementing Approov is required to always check if the signature and
expiration time of the Approov token is valid, and optionally to check if the
Approov token binding matches the one in the header.

For both the required and optional checks we always need to configure the Spring
framework security with the `ApproovAuthenticationProvider(approovConfig)`.

Now we need to configure what endpoints will perform the required and optional
checks, and for this we need to add `ApproovSecurityContextRepository(ApproovConfig approovConfig, boolean checkTokenBinding)`
and the `ApproovAuthenticationEntryPoint()`to the Spring framework security
context, plus the endpoint name and http verbs, were the authentication should
be triggered.

The `approovConfig` contains several information necessary to check the
Approov token, like the Approov secret used by the Approov cloud service to sign
the JWT token. For more details on what it contains you can inspect the code
[here](./src/main/java/com/criticalblue/approov/jwt/authentication/ApproovConfig.java).

Each time we add and endpoint to be protected by an Approov token we need to
tell if the Approov token binding is to be checked or not, and this is done with
the boolean flag `checkTokenBinding`.

In order to be able to have endpoints that perform only the required checks in
the Approov token, while at the same time having others endpoints where both the
required and optional checks must take place, we need to configure the Spring
framework security context with static subclasses of the main `WebSecurityConfig`
class, and this sub classes also need to implement the abstract
`WebSecurityConfigurerAdapter` class. This subclasses will be annotated with a
configuration order `@Order(n)`, thus their configuration order is important. So
where we define `Order(1)` we are telling to the Spring framework security
context to perform first the required checks on the Approov token, afterwards
with `@Order(2)` we perform the optional check for the Approov token binding,
and then with `@Order(3)` we proceed as usual, that in this demo is to
allow any request to the root endpoint `/` to be served without authentication
of any kind.


### Setup Environment

If you don't have already an `.env` file, then you need to create one in the
root of your project by using this [.env.example](./.env.example) as your
starting point.

The `.env` file must contain this five variables:

```env
APPROOV_TOKEN_BINDING_HEADER_NAME=Authorization

# Feel free to play with different secrets. For development only you can create them with:
# $ openssl rand -base64 64 | tr -d '\n'; echo
APPROOV_BASE64_SECRET=h+CX0tOzdAAR9l15bWAqvq7w9olk66daIH+Xk+IAHhVVHszjDzeGobzNnqyRze3lw/WVyWrc2gZfh3XXfBOmww==

APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN=true
APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN_BINDING=true
APPROOV_LOGGING_ENABLED=true
```


### The Code

Add the package [com.criticalblue.approov.jwt.authentication](./src/main/java/com/criticalblue/approov/jwt/authentication) to your current project and then configure it from the class in your project that extends the `WebSecurityConfigurerAdapter`.

Let's consider as a starting point an initial `WebSecurityConfig` without
requiring authentication for any of its endpoints:

```java
package com.criticalblue.approov.jwt;

import com.criticalblue.approov.jwt.authentication.*;
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
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/error");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.cors();

        http
            .httpBasic().disable()
            .formLogin().disable()
            .logout().disable()
            .csrf().disable()
            .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http
            .authorizeRequests()
            .antMatchers(HttpMethod.GET, "/").permitAll()
            .antMatchers(HttpMethod.GET, "/v2/hello").permitAll()
            .antMatchers(HttpMethod.GET, "/v2/shapes").permitAll()
            .antMatchers(HttpMethod.GET, "/v2/forms").permitAll();

        // the above endpoints declaration can be resumed to:
        // .antMatchers(HttpMethod.GET, "/**").permitAll()
    }
}
```

Now let's protect the endpoint for `/v2/shapes` and `/v2/forms` with an Approov token.

The `/v2/shapes` endpoint it will be protected only by the required checks for an
Approov token, while the `/v2/forms` endpoint will have the optional check for the
Approov token binding.

As already mentioned we will need to add to the `WebSecurityConfig` a subclass
for the endpoints we want to secure with only the required checks for an Approov
token, another for the endpoints secured with the required and optional checks
for an Aprroov token, and finally a subclass for endpoints that do not require
authentication.

So let's prepare the `WebSecurityConfig` with only a subclass that maintains the
access to all endpoints without any authentication.

Lets' add the subclass `ApiWebSecurityConfig`:

```java
package com.criticalblue.approov.jwt;

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
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:8002"));
        configuration.setAllowedMethods(Arrays.asList("GET"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/error");
    }

    @Configuration
    @Order(1)
    public static class ApiWebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.cors();

            http
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                .csrf().disable()
                .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            http
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/").permitAll()
                .antMatchers(HttpMethod.GET, "/v2/hello").permitAll()
                .antMatchers(HttpMethod.GET, "/v2/shapes").permitAll()
                .antMatchers(HttpMethod.GET, "/v2/forms").permitAll();

            // the above endpoints declaration can be resumed to:
            // .antMatchers(HttpMethod.GET, "/**").permitAll()
        }
    }
}
```

#### CORS Configuration

In order to integrate Approov we will need to use an `Approov-Token`, thus we
need to allow it in the CORS configuration.

If our Approov integration also uses the Approov token binding check, then we
also need to allow the header from where we want to retrieve the value we bind
to the Approov token payload in the mobile app, that in this demo is the
`Authorization` header.

So we add to the CORS configuration this 2 new lines:

```java
configuration.addAllowedHeader("Authorization");
configuration.addAllowedHeader("Approov-Token");
```

That will give us this new CORS configuration:

```java
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
```

#### Protecting the `/v2/shapes` endpoint

To protect the `/v2/shapes` endpoint we will add the subclass `ApproovWebSecurityConfig`:

```java
@Configuration
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
            .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http
            .securityContext()
            .securityContextRepository(new ApproovSecurityContextRepository(approovConfig, false))
            .and()
                .exceptionHandling()
                .authenticationEntryPoint(new ApproovAuthenticationEntryPoint())
            .and()
                .antMatcher("/v2/shapes")
                    .authorizeRequests()
                    .antMatchers(HttpMethod.GET, "/v2/shapes").authenticated();

            // Add here more endpoints that you need to protect with the required
            // checks for the Approov token.
            // .and()
            //     .antMatcher("/another-endpoint")
            //         .authorizeRequests()
            //         .antMatchers(HttpMethod.GET, "/another-endpoint").authenticated();
    }
}
```

and change the configuration order for subclass `ApiWebSecurityConfig` from `1`
to `2`:

```java
@Configuration
@Order(2)
public static class ApiWebSecurityConfig extends WebSecurityConfigurerAdapter {
    // omitted code ...

    // REMOVE ALSO THIS LINE
    .antMatchers(HttpMethod.GET, "/v2/shapes").permitAll()

    // omitted code ...
}
```

finally you can see that was removed the line of code allowing the endpoint
`/v2/shapes` to be reached without any authentication.


#### Protecting the `/v2/forms` endpoint

This endpoint also requires that we perform the optional check for the Approov token binding, thus to protect the `/v2/forms` endpoint another subclass is necessary.

Let's add the subclass `AproovPayloadWebSecurityConfig`:

```java
@Configuration
@Order(2)
public static class AproovPayloadWebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.cors();

        http
            .httpBasic().disable()
            .formLogin().disable()
            .logout().disable()
            .csrf().disable()
            .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http
            .securityContext()
            .securityContextRepository(new ApproovSecurityContextRepository(approovConfig, true))
            .and()
                .exceptionHandling()
                .authenticationEntryPoint(new ApproovAuthenticationEntryPoint())
            .and()
                .antMatcher("/v2/forms")
                    .authorizeRequests()
                    .antMatchers(HttpMethod.GET, "/v2/forms").authenticated();

            // Add here more endpoints that you need to protect with the
            // required and optional checks for the Approov token.
            // .and()
            //     .antMatcher("/another-endpoint")
            //         .authorizeRequests()
            //         .antMatchers(HttpMethod.GET, "/another-endpoint").authenticated();
    }
}
```

If you are paying attention you noticed that the configuration order is the same
as of the subclass `ApiWebSecurityConfig` in the previous step, thus we need to
change it again, this time from `2` to `3`:

```java
@Configuration
@Order(3)
public static class ApiWebSecurityConfig extends WebSecurityConfigurerAdapter {
    // omitted code ...

    // REMOVE ALSO THIS LINE
    .antMatchers(HttpMethod.GET, "/v2/forms").permitAll()

    // omitted code ...
}
```

and finally you can see that we removed the line of code allowing the endpoint
`/v2/forms` to be reached without any authentication.


#### Putting All-Together

After we implemented the Approov protection for the `/v2/shapes` and `/v2/forms`
endpoints the class `WebSecurityConfig` should look like:

```java
package com.criticalblue.approov.jwt;

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
                .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            http
                .securityContext()
                .securityContextRepository(new ApproovSecurityContextRepository(approovConfig, false))
                .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(new ApproovAuthenticationEntryPoint())
                .and()
                    .antMatcher("/v2/shapes")
                        .authorizeRequests()
                        .antMatchers(HttpMethod.GET, "/v2/shapes").authenticated();
        }
    }

    @Configuration
    @Order(2)
    public static class AproovPayloadWebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.cors();

            http
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                .csrf().disable()
                .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            http
                .securityContext()
                .securityContextRepository(new ApproovSecurityContextRepository(approovConfig, true))
                .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(new ApproovAuthenticationEntryPoint())
                .and()
                    .antMatcher("/v2/forms")
                        .authorizeRequests()
                        .antMatchers(HttpMethod.GET, "/v2/forms").authenticated();
        }
    }

    @Configuration
    @Order(3)
    public static class ApiWebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.cors();

            http
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                .csrf().disable()
                .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            http
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/**").permitAll();
        }
    }
}
```

#### The Code Difference

If we compare the initial implementation with the final result for the class
`WebSecurityConfig` we will see this difference:

```java
--- untitled (Previous)
+++ /home/sublime/workspace/java/spring/src/main/java/com/criticalblue/approov/jwt/WebSecurityConfig.java
@@ -1,6 +1,7 @@
 package com.criticalblue.approov.jwt;

 import com.criticalblue.approov.jwt.authentication.*;
+import org.springframework.core.annotation.Order;
 import org.springframework.security.config.annotation.web.builders.WebSecurity;
 import org.springframework.security.config.http.SessionCreationPolicy;
 import org.springframework.web.cors.CorsConfiguration;
@@ -25,6 +26,8 @@
         CorsConfiguration configuration = new CorsConfiguration();
         configuration.setAllowedMethods(Arrays.asList("GET"));
+        configuration.addAllowedHeader("Authorization");
+        configuration.addAllowedHeader("Approov-Token");
         UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
         source.registerCorsConfiguration("/**", configuration);
         return source;
@@ -35,27 +38,86 @@
         web.ignoring().antMatchers("/error");
     }

-    @Override
-    protected void configure(HttpSecurity http) throws Exception {
+    @Configuration
+    @Order(1)
+    public static class ApproovWebSecurityConfig extends WebSecurityConfigurerAdapter {

-        http.cors();
+        @Override
+        protected void configure(HttpSecurity http) throws Exception {

-        http
-            .httpBasic().disable()
-            .formLogin().disable()
-            .logout().disable()
-            .csrf().disable()
-            .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
-            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
+            http.cors();

-        http
-            .authorizeRequests()
-            .antMatchers(HttpMethod.GET, "/").permitAll()
-            .antMatchers(HttpMethod.GET, "/v2/hello").permitAll()
-            .antMatchers(HttpMethod.GET, "/v2/shapes").permitAll()
-            .antMatchers(HttpMethod.GET, "/v2/forms").permitAll();
+            http
+                .httpBasic().disable()
+                .formLogin().disable()
+                .logout().disable()
+                .csrf().disable()
+                .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
+                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

-        // the above endpoints declaration can be resumed to:
-        // .antMatchers(HttpMethod.GET, "/**").permitAll()
+            http
+                .securityContext()
+                .securityContextRepository(new ApproovSecurityContextRepository(approovConfig, false))
+                .and()
+                    .exceptionHandling()
+                    .authenticationEntryPoint(new ApproovAuthenticationEntryPoint())
+                .and()
+                    .antMatcher("/v2/shapes")
+                        .authorizeRequests()
+                        .antMatchers(HttpMethod.GET, "/v2/shapes").authenticated();
+        }
     }
-}
+
+    @Configuration
+    @Order(2)
+    public static class AproovPayloadWebSecurityConfig extends WebSecurityConfigurerAdapter {
+
+        @Override
+        protected void configure(HttpSecurity http) throws Exception {
+
+            http.cors();
+
+            http
+                .httpBasic().disable()
+                .formLogin().disable()
+                .logout().disable()
+                .csrf().disable()
+                .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
+                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
+
+            http
+                .securityContext()
+                .securityContextRepository(new ApproovSecurityContextRepository(approovConfig, true))
+                .and()
+                    .exceptionHandling()
+                    .authenticationEntryPoint(new ApproovAuthenticationEntryPoint())
+                .and()
+                    .antMatcher("/v2/forms")
+                        .authorizeRequests()
+                        .antMatchers(HttpMethod.GET, "/v2/forms").authenticated();
+        }
+    }
+
+    @Configuration
+    @Order(3)
+    public static class ApiWebSecurityConfig extends WebSecurityConfigurerAdapter {
+
+        @Override
+        protected void configure(HttpSecurity http) throws Exception {
+
+            http.cors();
+
+            http
+                .httpBasic().disable()
+                .formLogin().disable()
+                .logout().disable()
+                .csrf().disable()
+                .authenticationProvider(new ApproovAuthenticationProvider(approovConfig))
+                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
+
+            http
+                .authorizeRequests()
+                .antMatchers(HttpMethod.GET, "/**").permitAll();
+        }
+    }
+}
```


As we can see the Approov integration in a current server is simple, easy and is
done with just a few lines of code.

If you have not done it already, now is time to follow the
[Approov Shapes API Server](./docs/approov-shapes-api-server.md) walk-through
to see and have a feel for how all this works.


## PRODUCTION

In order to protect the communication between your mobile app and the API server
is important to only communicate hover a secure communication channel, aka HTTPS.

Please bear in mind that HTTPS on its own is not enough, certificate pinning
must be also used to pin the connection between the mobile app and the API
server in order to prevent [Man in the Middle Attacks](https://approov.io/docs/mitm-detection.html).

We do not use certificate pinning in this Approov integration example
because we want to be able to demonstrate, via Postman how, the API works.

However in production will be mandatory to implement [certificate pinning](https://approov.io/docs/mitm-detection.html#id1).

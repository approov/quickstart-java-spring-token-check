# Approov Token Integration Example

This Approov integration example is from where the code example for the [Approov token check quickstart](/docs/APPROOV_TOKEN_QUICKSTART.md) is extracted, and you can use it as a playground to better understand how simple and easy it is to implement [Approov](https://approov.io) in a Java Spring API server.

## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Requirements](#requirements)
* [Try the Approov Integration Example](#try-the-approov-integration-example)


## Why?

To lock down your API server to your mobile app. Please read the brief summary in the [README](/README.md#why) at the root of this repo or visit our [website](https://approov.io/product.html) for more details.

[TOC](#toc---table-of-contents)


## How it works?

The Java Spring API server is very simple and only replies to the endpoint `/` with the message:

```json
{"message": "Hello, World!"}
```

You can find the endpoint definition [here](./src/main/java/com/criticalblue/approov/jwt).

Take a look at the [`verifyApproovToken()`](./src/main/java/com/criticalblue/approov/jwt/authentication/ApproovAuthentication.java) function to see the simple code for the check.

For more background on Approov, see the overview in the [README](/README.md#how-it-works) at the root of this repo.


[TOC](#toc---table-of-contents)


## Requirements

To run this example you will need to have installed:

* [OpenJDK](https://openjdk.java.net/install/) - This server example uses version `11.0.3`. It should work with earlier or later versions but was not tested.
* [Java Spring](https://docs.spring.io/spring-boot/docs/current/reference/html/getting-started.html#getting-started.installing) - Version `2.6.4` of the Spring Framework plugin is being used. The code should work with prior versions but wasn't tested.

[TOC](#toc---table-of-contents)


## Try the Approov Integration Example

First, you need to set the dummy secret in the `/servers/hello/src/approov-protected-server/token-check/.env` file as explained [here](/README.md#the-dummy-secret).

Second, you need to build the server with gradle. From the `./servers/hello/src/approov-protected-server/token-check` folder execute:

```bash
./gradlew build
```

Now, you can run this example from the `/servers/hello/src/approov-protected-server/token-check` folder with:

```bash
source .env && ./gradlew bootRun
```

Next, you can test that it works with:

```text
curl -iX GET 'http://localhost:8002'
```

The response will be a `400` bad request:

```text
HTTP/1.1 400
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json
Transfer-Encoding: chunked
Date: Fri, 11 Mar 2022 19:59:11 GMT
Connection: close

{}
```

The reason you got a `400` is because no Approoov token isn't provided in the headers of the request.

Finally, you can test that the Approov integration example works as expected with this [Postman collection](/README.md#testing-with-postman) or with some more cURL requests [examples](/README.md#testing-with-curl).

[TOC](#toc---table-of-contents)

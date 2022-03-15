# Unprotected Server Example

The unprotected example is the base reference to build the [Approov protected servers](/servers/hello/src/approov-protected-server/). This a very basic Hello World server.


## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Requirements](#requirements)
* [Try It](#try-it)


## Why?

To be the starting building block for the [Approov protected servers](/servers/hello/src/approov-protected-server/), that will show you how to lock down your API server to your mobile app. Please read the brief summary in the [README](/README.md#why) at the root of this repo or visit our [website](https://approov.io/product.html) for more details.

[TOC](#toc---table-of-contents)


## How it works?

The Java Spring API server is very simple and only replies to the endpoint `/` with the message:

```json
{"message": "Hello, World!"}
```

You can find the endpoint definition [here](./src/main/java/com/criticalblue/approov/jwt).

[TOC](#toc---table-of-contents)


## Requirements

To run this example you will need to have installed:

* [OpenJDK](https://openjdk.java.net/install/) - This server example uses version `11.0.3`. It should work with earlier or later versions but was not tested.
* [Java Spring](https://docs.spring.io/spring-boot/docs/current/reference/html/getting-started.html#getting-started.installing) - Version `2.6.4` of the Spring Framework plugin is being used. The code should work with prior versions but wasn't tested.

[TOC](#toc---table-of-contents)


## Try It

First build the server with gradle. From the `./servers/hello/src/unprotected-server` folder execute:

```bash
./gradlew build
```

Now, you can run this example from the `./servers/hello/src/unprotected-server` folder with:

```bash
source .env && ./gradlew bootRun
```

Finally, you can test that it works with:

```text
curl -X GET 'http://localhost:8002'
```

The response will be:

```json
{"message":"Hello, World!"}
```

[TOC](#toc---table-of-contents)

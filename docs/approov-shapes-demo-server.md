# APPROOV SHAPES DEMO SERVER

The Approov Shapes Demo Server contains endpoints with and without the Approov
protection. The protected endpoints differ in the sense that one uses the
optional custom payload claim in the Approov token.

We will demonstrate how to call each API endpoint with screen-shots from Postman
and from the shell terminal. Postman is used here as an easy way to demonstrate
how you can play with the Approov integration in the API server, but to see a
real demo of how Approov would work in production you need to request a demo
[here](https://info.approov.io/demo).

When presenting the screen-shots we will present them as 2 distinct views. The
Postman view will tell how we performed the request and what response we got
back and the shell view show us the log entries that lets us see the result of
checking the Approov token and how the requested was handled.


## REQUIREMENTS

The same as we defined [here](README.md#requirements) when explain how to
integrate Approov.


## INSTALL

### Approov Shapes Demo Server

Lets's start by cloning the demo:

```bash
$ git clone https://github.com/approov/java-spring_approov-shapes-demo-server.git

$ cd java-spring_approov-shapes-demo-server
```

### Development Environment

In order to have an agnostic development environment through this tutorial we
recommend the use of Docker, that can be installed by following [the official
instructions](https://docs.docker.com/install/) for your platform.

A bash script `./stack` is provided in the root of the demo to make easy to use
the docker stack to run this demo.

Show the usage help with:

```bash
$ ./stack --help

DOCKER STACK CLI WRAPPER

This bash script is a wrapper around docker for easier use of the docker stack
in this project.

Signature:
  ./stack [options] <command> <args>


Usage:
  ./stack
  ./stack [-d, --detach] [-h, --help] [-p, --port] [-u, --user] <command> <args>


Options:
  -d, --detach    Runs the docker container detached from the terminal.
                    $ ./stack --detach up

  -h, --help      Shows this help.
                    $ ./stack --help

  -p, --port      The host port to access the docker container.
                    $ ./stack --port 8000 up

  -u, --user      Run the docker container under the given user name or uid.
                    $ ./stack --user root shell

Commands/Args:
  build           Builds the docker image for this stack.
                    $ ./stack build

  down            Stops and removes the docker container.
                    $ ./stack down

  up              Starts the docker container with the Java server running.
                  Defaults to on port 5000.
                    $ ./stack up
                    $ ./stack --detach up
                    $ ./stack --port 8000 up
                    $ ./stack --detach --port 8000 up

  shell <name>    Starts a shell in the docker container:
                    $ ./stack shell
                    $ ./stack shell bash
                    $ ./stack --user 0 shell
```

#### Building the docker image:

```bash
./stack build
```
> The resulting docker image will contain the Approov Shapes Demo Server in Java.

#### Getting a shell terminal inside the docker container:

```bash
./stack shell
```
> If you choose to continue following this demo using Docker, then all subsequent
  shell commands must be executed from this shell terminal.

## SETUP

### Environment File

Lets' copy the `.env.example` to `.env` with the command:

```bash
cp .env-example .env
```

No modifications are necessary to the newly created `.env` in order to run the
demo with the provided Postman collection.

### Building the Project

Lets' try to build the project:

```bash
$ ./gradlew build

# omitted output ...

BUILD SUCCESSFUL in 33s
5 actionable tasks: 3 executed, 2 up-to-date
```

The build went successful, thus we are ready to start playing around with the
server.

## RUNNING THE APPROOV SHAPES DEMO SERVER

We will run this demo first with Approov enabled and a second time with Approov
disabled. When Approov is enabled any API endpoint protected by an Approov token
will have the request denied with a `403` response for each time the Approov
token check fails for any reason. When Approov is disabled the check still
takes place but no requests are denied, only the reason for the failure is
logged.

### The logs

When a request is issued from Postman you can see the logs being printed to your
shell terminal where you can see all log entries about requests protected by
Approov, and compare the logged messages with the results returned to Postman
for failures or success in the validation of the Approov token.

An example for an accepted request:

```bash
2019-04-26 11:42:30.503  INFO 17062 --- [nio-5000-exec-2] c.c.a.j.a.ApproovAuthentication          : Request approved with a valid Approov token.
2019-04-26 11:42:30.503  INFO 17062 --- [nio-5000-exec-2] c.c.a.j.a.ApproovAuthentication          : Request approved with a valid custom payload claim in the Approov token.
2019-04-26 11:42:30.524  INFO 17062 --- [nio-5000-exec-2] c.c.a.j.a.ApproovAuthentication          : Serving request for endpoint '/forms', that is protect by an Approov Token.
```

Example for a rejected request:

```bash
2019-04-26 11:43:43.083 ERROR 17062 --- [nio-5000-exec-5] c.c.a.j.a.ApproovAuthenticationException : JWT expired at 2019-04-12T15:35:49Z. Current time: 2019-04-26T10:43:43Z, a difference of 1192074083 milliseconds.  Allowed clock skew: 0 milliseconds. -> See: com.criticalblue.approov.jwt.authentication.ApproovAuthentication.checkWith(ApproovAuthentication.java:98)

```

### Starting Postman

Open Postman and import [this collection](https://gitlab.com/snippets/1799104/raw)
that contains all the API endpoints prepared with all scenarios we want to
demonstrate.

The Approov tokens used in Postman during this demo have been generated manually
with [this script](./bin/generate-token). Feel free to play around with the
script to generate different `Approov-Token` headers to be used in the Postman
requests.


### Approov Tokens Generation

The script to generate the Approov tokens used in the Postman collection is very
easy to use.

To show the usage help:

```bash
$ ./bin/generate-token --help
GENERATE APPROOV TOKEN CLI

To be used only to generate Approov tokens for testing purposes during development.

Usage:
    generate-token
    generate-token [--expire EXPIRE] [--claim CLAIM] [--claim-example] [--secret SECRET]

Options:
    --expire EXPIRE  The Approov token expire time in minutes [default: 5].
    --claim CLAIM    The base64 encode sha256 hash of the custom payload claim for the Approov token.
    --claim-example  Same as --claim but using an hard-coded claim example.
    --secret SECRET  The base64 encoded secret to sign the Approov token for test purposes.
    -h --help        Show this screen.
    -v --version     Show version.
```

With default 5 minutes expire time and without a custom payload claim:

```bash
$ ./bin/generate-token
Token:
 eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTYyNzQxNjMuMzY1OTE0fQ.eO_AHCK9TGKD0-BtdjRDD2aZHd4VMyGLMdF-6-bPsHw
```

With custom expire time and the built-in custom claim example:

```bash
./bin/generate-token --expire 10 --claim-example
Token:
 eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXkiOiJsOFRUcXh5b1N3bHpTYmY4NEY3Z3B5QVdtY1hYL0JJWWxpdjBiQlowR2ZFPSIsImV4cCI6MTU1NjI3NDQyNi4zOTYyNjN9.v8nSiVZnjGX1MptLVbFxBY1Llzdq_zSCi2OJLpzVc0o
```

Feel free to try all the options...


### Starting the Java Server

To start the server we want to issue the command:

```bash
source .env && ./gradlew bootRun
```

> **NOTE**:
>
> If you decide to run the Java server from your IDE, then you need to set all
> the environments variables in the `.env` file in your IDE.

After the Java server is up and running it will be available at http://localhost:5000.

### Endpoint Not Protected by Approov

This endpoint does not benefit from Approov protection and the goal here is to
show that both Approov protected and unprotected endpoints can coexist in the
same API server.

#### /hello

**Postman View:**

![postman hello endpoint](./assets/img/postman-hello.png)
> As we can see we have not set any headers.

**Shell view:**

![shell terminal hello endpoint](./assets/img/shell-hello.png)
> As expected the logs don't have entries with Approov errors.


**Request Overview:**

Looking into the Postman view, we can see that the request was sent without the
`Approov-Token` header and we got a `200` response, and looking to the shell
view we can see a log entry telling that this is a endpoint not protected by an
Approov token.

### Endpoints Protected by an Approov Token

This endpoint requires a `Approov-Token` header and depending on the boolean
value for the environment variable `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN` we will
have 2 distinct behaviours. When being set to `true` we refuse to fulfill the
request and when set to `false` we will let the request pass through. For both
behaviours we log the result of checking the Approov token.

The default behaviour is to have `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN` set to
`true`, but you may feel more comfortable to have it setted to `false` during
the initial deployment, until you are confident that you are only refusing bad
requests to your API server.

#### /shapes - missing the Approov token header

Make sure that the `.env` file contains `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN` set to `true`.

Cancel current server session with `ctrl+c` and start it again with:

```bash
source .env && ./gradlew bootRun
```

**Postman view:**

![Postman - shapes endpoint without an Approov token](./assets/img/postman-shapes-missing-approov-token.png)
> As we can see we have not set any headers.

**Shell view:**

![Shell - shapes endpoint without an Approov token](./assets/img/shell-shapes-missing-approov-token.png)
> No log entries for Approov in this request?

**Request Overview:**

Looking to the Postman view we can see that we forgot to add the `Approov-Token`
header, thus a `403` response is returned.

In the shell view we do not see any log entries, because this is handled by the
Java Spring framework security, and we are tracking only Approov logs.

**Let's see the same request with Approov disabled**

Make sure that the `.env` file contains `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN` set to `false`.

Cancel current server session with `ctrl+c` and start it again with:

```bash
source .env && ./gradlew bootRun
```

**Postman view:**

![Postman - shapes endpoint without an Approov token and approov disabled](./assets/img/postman-shapes-missing-approov-token-and-approov-disabled.png)
> Did you notice that now we have the same exact response?

**Shell view:**

![Shell - shapes endpoint without an Approov token and approov disabled](./assets/img/shell-shapes-missing-approov-token-and-approov-disabled.png)
> We continue without any logs entries for Approov...

**Request Overview:**

We continue to not provide the `Approov-Token` header and even having disabled
to abort the request on an invalid Approov token does not change the response.
This happens because this request never arrives to the Approov implementation,
and the Java Spring framework security doesn't allow the request to proceed,
because it was configured to expect the `Approov-Token` on this endpoint.

So its with no surprise that we continue to not see any log entries in the shell.


#### /shapes - Invalid Approov token header

Make sure that the `.env` file contains `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN` set to `true`.

Cancel current server session with `ctrl+c` and start it again with:

```bash
source .env && ./gradlew bootRun
```

**Postman view:**

![Postman - shapes endpoint with an invalid Approov token](./assets/img/postman-shapes-invalid-token.png)
> Did you notice the `Approov-Token` with an invalid JWT token?

**Shell view:**

![Shell - shapes endpoint with an invalid Approov token](./assets/img/shell-shapes-invalid-token.png)
> Can you spot what is the reason for the `403` response?

**Request Overview:**

In Postman we issue the request with an invalid `Approov-Token` header, that is
a normal string, not a JWT token, thus we get back a `403` response.

Looking to shell view we can see that the logs is telling us that the reason is
an invalid JWT token, that doesn't contain enough segments.


**Let's see the same request with Approov disabled**

Make sure that the `.env` file contains `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN` set to `false`.

Cancel current server session with `ctrl+c` and start it again with:

```bash
source .env && ./gradlew bootRun
```

**Postman view:**

![Postman - shapes endpoint with an invalid Approov token and approov disabled](./assets/img/postman-shapes-invalid-token-and-approov-disabled.png)


**Shell view:**

![Shell - shapes endpoint with an invalid Approov token and approov disabled](./assets/img/shell-shapes-invalid-token-and-approov-disabled.png)


**Request Overview:**

In Postman, instead of sending a valid JWT token, we continue to send the
`Approov-Token` header as a normal string, but this time we got a `200` response
back because Approov is disabled, thus not blocking the request.

In the shell view we continue to see the same reason for the Approov token
validation failure.


#### /shapes - Valid Approov token header

Make sure that the `.env` file contains `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN` set to `true`.

Cancel current server session with `ctrl+c` and start it again with:

```bash
source .env && ./gradlew bootRun
```

> **NOTE**:
>
> For your convenience the Postman collection includes a token that only expires
> in a very distant future for this call "Approov Token with valid signature and
> expire time". For the call "Expired Approov Token with valid signature" an
> expired token is also included.


**Postman view with token correctly signed and not expired token:**

![Postman - shapes endpoint with a valid Approov token](./assets/img/postman-shapes-valid-token.png)

**Postman view with token correctly signed but this time is expired:**

![Postman - shapes endpoint with a expired Approov token](./assets/img/postman-shapes-expired-token.png)


**Shell view:**

![Shell - shapes endpoint with a valid and with a expired Approov token](./assets/img/shell-shapes-valid-and-expired-token.png)


**Request Overview:**

We used an helper script to generate an Approov Token that was valid for 1
minute.

In Postman we performed 2 requests with the same token and the first one was
successful, but the second request, performed 2 minutes later, failed with a
`403` response because the token have already expired as we can see by the
log messages in the shell view.


**Let's see the same request with Approov disabled**

Make sure that the `.env` file contains `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN` set to `false`.

Cancel current server session with `ctrl+c` and start it again with:

```bash
source .env && ./gradlew bootRun
```
**Postman view with token valid for 1 minute:**

![Postman - shapes endpoint with a valid Approov token and Approov disabled](./assets/img/postman-shapes-valid-token-and-approov-disabled.png)

**Postman view with same token but this time is expired:**

![Postman - shapes endpoint with a expired Approov token and Approov disabled](./assets/img/postman-shapes-expired-token-and-approov-disabled.png)

**Shell view:**

![Shell - shapes endpoint with a valid, with an expired Approov token and Approov disabled](./assets/img/shell-shapes-approov-disabled-with-valid-and-expired-token.png)
> Can you spot where is the difference between this shell view and the previous one?

**Request Overview:**

We repeated the process to generate the Appoov token with 1 minute of expiration
time.

Once more we performed the 2 requests with the same token and with 2 minutes
interval between them but this time we got both of them with `200` responses.

If we look into the shell view we can see that the first request have
a valid token and in the second request the token is not valid because is
expired, but once Approov is disabled the request is accepted.

### Endpoints Protected by an Approov Token with Custom Payload Claim

A custom payload claim is optional in any Approov token and you can read
more about them [here](./../README.md#approov-validation-process).

The requests where the custom payload claim is checked will be rejected on
failure but only if the environment variable
`APPROOV_ABORT_REQUEST_ON_INVALID_CUSTOM_PAYLOAD_CLAIM` is set to `true`. To
bear in mind that before this check is done the request have already been
through the same flow we have described for the `/shapes` endpoint.


#### /forms - Invalid Custom Payload Claim in the Approov token

Make sure that the `.env` file contains `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN`
and `APPROOV_ABORT_REQUEST_ON_INVALID_CUSTOM_PAYLOAD_CLAIM` set to `true`.

Cancel current server session with `ctrl+c` and start it again with:

```bash
source .env && ./gradlew bootRun
```

**Postman view:**

![Postman - forms endpoint with invalid custom payload claim](./assets/img/postman-forms-invalid-custom-payload-claim.png)

**Shell view:**

![Shell - forms endpoint with invalid custom payload claim](./assets/img/shell-forms-invalid-custom-payload-claim.png)

**Request Overview:**

In Postman we added an Approov token with a custom payload claim not matching
the Authorization token, thus the API server rejects the request with a `403`
response.

While we can see in the shell view that the request is accepted for the Approov
token itself, afterwards the request is rejected with an exception, due to an
invalid custom payload contained in the Approov token.

> **IMPORTANT**:
>
> When decoding the Approov token we only check if the signature and expiration
> time are valid, nothing else within the token is checked.
>
> The custom payload claim check works on the decoded Approov token to validate
> if the claim included in the payload key `pay` is the expected one.


**Let's see the same request with Approov disabled**

Make sure that the `.env` file contains `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN`
and `APPROOV_ABORT_REQUEST_ON_INVALID_CUSTOM_PAYLOAD_CLAIM` set to `false`.

Cancel current server session with `ctrl+c` and start it again with:

```bash
source .env && ./gradlew bootRun
```

**Postman view:**

![Postman - forms endpoint with invalid custom payload claim](./assets/img/postman-forms-invalid-custom-payload-claim-with-approov-disabled.png)

**Shell view:**

![Shell - forms endpoint with invalid custom payload claim](./assets/img/shell-forms-invalid-custom-payload-claim-with-approov-disabled.png)

**Request Overview:**

We still have the invalid custom payload claim in the Approov token but once we
have disabled Approov we now have a `200` response.

In the shell view we can confirm that the log entry still reflects that the
custom payload claim is invalid, but this time a response is returned, and this
is is because Approov is now disabled.


#### /forms - Valid Custom Payload Claim in the Approov token

Make sure that the `.env` file contains `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN`
and `APPROOV_ABORT_REQUEST_ON_INVALID_CUSTOM_PAYLOAD_CLAIM` set to `true`.

Cancel current server session with `ctrl+c` and start it again with:

```bash
source .env && ./gradlew bootRun
```

**Postman view:**

![Postman - forms endpoint with valid custom payload claim](./assets/img/postman-forms-valid-custom-payload-claim.png)

**Shell view:**

![Shell - forms endpoint with valid custom payload claim](./assets/img/shell-forms-valid-custom-payload-claim.png)

**Request Overview:**

In the Postman view the Approov token header contains a valid custom payload
claim, thus when we perform the request the API server doesn't reject it and a
`200` response is sent back.

The shell view confirms us that the custom payload claim is valid and we can
also see the log entry confirming that the request was served.

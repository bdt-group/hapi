# hapi

An HTTP client designed for REST API

## Overview

`hapi` is a library that provides functions to request REST API backends. It does many
things under the hood, like DNS resolving, request retrying, JSON validation and so on.

The API functions are exported from [hapi](#hapi-module) and [hapi_json](#hapi_json-module) modules.
Other modules (like `hapi_xml`) can be introduced later.

For [hapi_json](#hapi_json-module) module the library is using [jiffy](https://github.com/davisp/jiffy)
codec to decode and [yval](https://github.com/zinid/yval) validator to validate received JSON.

## hapi module

### Types

The following types are exported from `hapi` module:

- `uri()`: an URI represented in format produced by `http_uri:parse/1`.

- `req_opts()`: a map holding request options. All options are optional.
  Available options are:

  - `timeout: non_neg_integer() | {abs, non_neg_integer()}`:
    A non-negative integer representing either timeout in milliseconds or
    an absoulute time in milliseconds which denotes when the function
    must be completed. It is important to stress that for `{abs, Time}`
    the `Time` is computed using `erlang:system_time(millisecond)`, but
    **NOT** `erlang:monotonic_time(millisecond)`. If you assume the later,
    you get an incorrect behaviour. Also note that several HTTP
    requests can be performed during a single function call, so don't
    confuse this option with `timeout_per_request` (see bellow).
    The default value is `30000`.

  - `timeout_per_request: non_neg_integer()`:
    A non-negative integer representing timeout in milliseconds that
    is used for a particual HTTP request. Since many HTTP requests
    may be performed during a single function call (due to multiple
    resolved IP addresses or several attempts being repeated),
    the value of the option must be selected the way that it fits into
    general timeout represented by `timeout` option (see above). The
    default is the value of `timeout` option divided by the number of
    resolved IP addresses, e.g. if `timeout` is `5000` milliseconds
    and three addresses have been resolved, a request to each of them
    will be completed within `1666` milliseconds.

  - `max_retries: non_neg_integer() | infinity`. A maximum number of retries
    to be performed. The default is `infinity`, i.e. the request is to
    be repeated until it is succeeded or timeout is reached. In particular,
    the value of zero (0) means no retries will be performed.

  - `retry_base_timeout: non_neg_integer()`:
    A time (in milliseconds) to wait before next try after first
    failed attempt. The value is exponentially increased for further retries
    (if any). The default value is `1000` milliseconds.

  - `auth`: a map representing HTTP authorization options. All options are mandatory.
    The options are:
    - `type: atom()`: authorization type. Currently only `basic` is supported.
    - `username: iodata()`: a user name to use for the authorization.
    - `password: iodata()`: a password to use for the authorization.

  - `headers: [{binary(), binary()}]`: Additional HTTP headers. The default is
    an empty list (`[]`).

  - `ip_family: [inet | inet6, ...]`: An IP address version to resolve: `inet`
    stands for IPv4 and `inet6` stands for IPv6. The default is `[inet]`
    which means that only IPv4 addresses will be resolved.

  - `use_pool: boolean()`: Whether to use connection pool or not. The default
    is `false`. The pool itself is configured using application environment
    variables `pool_size` and `max_queue` with default values being `10` and `10000`
    respectively. The `pool_size` sets the **maximum** number of connections
    per endpoint (i.e. per IP-address/port pair). The pool is dynamic in the sense
    that it keeps only required number of connections, i.e. new connections
    are added to the pool only when all other connections are request-busy.
    When the number of connections in the pool reaches `pool_size` number,
    no new connections are added to the pool.
    The variable `max_queue` defines the maximum number of requests in the
    pool request queue. When the queue is overfilled (i.e. `max_queue` is reached)
    the pool is first cleaned up from overdue requests, then, if the request queue
    is still filled with more than **80%** of its capacity, the pool is completely
    cleared with all its pending requests being discarded with the corresponding
    error.

- `method() :: get | post | delete`: an HTTP method.

- `headers()`: HTTP headers represented as `[{binary(), binary()}]`.

- `http_reply() :: {Status :: non_neg_integer(), Headers :: headers(), Body :: binary()}`:
  A successful HTTP reply.

- `error_reason()`: a `term()` representing an error reason.

### get/1,2

```erl
-spec get(URI :: uri()) -> {ok, http_reply()} | {error, error_reason()}.
-spec get(uri(), req_opts()) -> {ok, http_reply()} | {error, error_reason()}.
```
Performs an HTTP GET request.

### post/2,3

```erl
-spec post(URI :: uri(), Body :: iodata()) -> {ok, http_reply()} | {error, error_reason()}.
-spec post(uri(), iodata(), req_opts()) -> {ok, http_reply()} | {error, error_reason()}.
```
Performs an HTTP POST request.

### delete/1,2

```erl
-spec delete(uri()) -> {ok, http_reply()} | {error, error_reason()}.
-spec delete(uri(), req_opts()) -> {ok, http_reply()} | {error, error_reason()}.
```
Performs an HTTP DELETE request.

### format_error/1

```erl
-spec format_error(Reason :: error_reason()) -> string().
```
Returns a descriptive string of the error reason in English.

### proxy_status/1

```erl
-spec proxy_status(http_reply() | error_reason()) -> non_neg_integer().
```
Given an HTTP reply or an error reason, produces the corresponding HTTP status code.
Useful for proxying responses downstream.

## hapi_json module

### Types

The following types are exported from `hapi_json` module:

- `problem_report()`: A map representing problem details as described in
  [RFC7807](https://tools.ietf.org/html/rfc7807) - the module supports the RFC
  and is able to understand `application/problem+json` content type.
  The map has the following structure:
  ```erl
  #{status := non_neg_integer(),
    type => binary(),
    title => binary(),
    detail => binary(),
    _ => term()}.
  ```
  All keys represent JSON fields explained in the RFC.

- `json_error_reason()`: a `term()` representing the reason of JSON decoding/validation failure.

- `error_reason()`: a `term()` representing an error reason. Not to be confused with
  `hapi:error_reason()` and hence, **NOT** to be used in `hapi:format_error/1`.

### get/2,3

```erl
-spec get(URI :: hapi:uri(),
          Validator :: yval:validator(T)) -> {ok, T | no_content} | {error, error_reason()}.
-spec get(URI :: hapi:uri(),
          Validator :: yval:validator(T),
          Options :: hapi:req_opts()) -> {ok, T | no_content} | {error, error_reason()}.
```
Performs an HTTP GET request and decodes JSON response body.
The `Validator` is used to validate decoded JSON.

### post/3,4

```erl
-spec post(URI :: hapi:uri(),
           JSON :: jiffy:json_value(),
           Validator :: yval:validator(T)) -> {ok, T | no_content} | {error, error_reason()}.

-spec post(URI :: hapi:uri(),
           JSON :: jiffy:json_value(),
           Validator :: yval:validator(T),
           Options :: hapi:req_opts()) -> {ok, T | no_content} | {error, error_reason()}.
```
Performs an HTTP POST request and decodes JSON response body.
The `Validator` is used to validate decoded JSON.

### delete/2,3

```erl
-spec delete(URI :: hapi:uri(),
             Validator :: yval:validator(T)) -> {ok, T | no_content} | {error, error_reason()}.
-spec delete(URI :: hapi:uri(),
             Validator :: yval:validator(T),
             Options :: hapi:req_opts()) -> {ok, T | no_content} | {error, error_reason()}.
```
Performs an HTTP DELETE request and decodes JSON response body.
The `Validator` is used to validate decoded JSON.

### decode/2

```erl
-spec decode(Data :: binary(),
             Validator :: yval:validator(T)) -> {ok, T | no_content} | {error, json_error_reason()}.
```
Decodes and validates JSON represented as `binary()`.

### encode/1

```erl
-spec encode(jiffy:json_value()) -> iodata().
```
Encodes JSON.

### format_error/1

```erl
-spec format_error(error_reason()) -> string().
```
Returns a descriptive string of the error reason in English.
You can also format error reasons produced by [hapi](#hapi-module) module,
but **NOT** other way around.

### proxy_status/1

```erl
-spec proxy_status(error_reason()) -> non_neg_integer().
```
Given an HTTP reply or an error reason, produces the corresponding HTTP status code.
Useful for proxying responses downstream.

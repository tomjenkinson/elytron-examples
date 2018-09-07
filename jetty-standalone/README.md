### Securing an embedded Jetty server using Elytron

This example shows how to secure an embedded Jetty server using HTTP BASIC authentication backed by Elytron.

1. First build the ```netty``` branch from the ```elytron-web``` fork in the ```wildfly-security-incubator``` (this
branch contains the ```ElytronAuthenticator``` and ```ElytronRunAsHandler``` integration classes that are used in this example
application to secure Jetty using Elytron):

```
    git clone https://github.com/wildfly-security-incubator/elytron-web
    cd elytron-web
    git checkout netty
    mvn clean install
```

2. Next take a look at the ```org.wildfly.security.examples.HelloWorld``` class in this example that starts an embedded
Jetty server, creates an Elytron map-backed security realm, and adds the configuration necessary to secure the embedded
Jetty server using Elytron. Notice that the created security realm has two users, ```alice``` and ```bob```, with passwords
```alice123+``` and ```bob123+```, respectively. Also notice that ```alice``` has both the ```employee``` and ```admin``` roles
but ```bob``` only has the ```employee``` role.


3. Build and run this example application:

```
    mvn clean install exec:exec
```

4. First attempt to access the application as ```bob```. Since accessing the application requires ```admin``` role, you'll
see an HTTP 403 error. Next, attempt to access the application as ```alice```. Since ```alice``` has ```admin``` role,
you'll be able to successfully log in.

```
    http://localhost:8080/secured
```

5. It is also possible to plug in a custom HTTP authentication mechanism in this example. Take a look at
```org.wildfly.security.examples.CustomHeaderHttpAuthenticationMechanism```. It implements the Elytron
```HttpServerAuthenticationMechanism``` interface to provide a definition of an HTTP server side authentication
mechanism. This example custom HTTP authentication mechanism requires the username/password to be provided
via ```CUSTOM-USERNAME``` and ```CUSTOM-PASSWORD``` headers. The ```org.wildfly.security.examples.CustomMechanismFactory```
implements the Elytron ```HttpServerAuthenticationMechanismFactory``` interface and is used to create instances of
our ```CustomHeaderHttpAuthenticationMechanism```. To make use of this custom authentication mechanism, uncomment the following line
in ```org.wildfly.security.examples.HelloWorld#createElytronAuthenticator```:

```
// Uncomment the following line to create an HttpServerAuthenticationMechanismFactory that can be used to provide our
// custom HTTP authentication mechanism
//httpServerMechanismFactory = new CustomMechanismFactory();

```

Then rebuild and run the example application:


```
    mvn clean install exec:exec
```

Now try accessing the application:

```
curl -v http://localhost:8080/secured -u alice:alice123+
```

You should see an error message which indicates that the username and password must be specified using the custom headers:

```
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
* Server auth using Basic with user 'alice'
> GET /secured HTTP/1.1
> Host: localhost:8080
> Authorization: Basic YWxpY2U6YWxpY2UxMjMr
> User-Agent: curl/7.53.1
> Accept: */*
>
< HTTP/1.1 401 Unauthorized
< Date: Mon, 24 Sep 2018 15:36:51 GMT
< CUSTOM-MESSAGE: Please resubmit the request with a username specified using the CUSTOM-USERNAME header and a password specified using the CUSTOM-PASSWORD header.
< Content-Length: 0
< Server: Jetty(9.4.11.v20180605)
<
* Connection #0 to host localhost left intact
```

Now try accessing the application by making use of the custom headers:


```
curl -v http://localhost:8080/secured -H "CUSTOM-USERNAME:alice" -H "CUSTOM-PASSWORD:alice123+"
```

You should see the following output which indicates that you were able to successfully login as ```alice```:

```
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
* Server auth using Basic with user 'alice'
> GET /secured HTTP/1.1
> Host: localhost:8080
> Authorization: Basic YWxpY2U6YWxpY2UxMjMr
> User-Agent: curl/7.53.1
> Accept: */*
>
< HTTP/1.1 200 OK
< Date: Mon, 24 Sep 2018 15:16:31 GMT
< Content-Type: text/html;charset=utf-8
< Content-Length: 265
< Server: Jetty(9.4.11.v20180605)
<
<html>
  <head><title>Embedded Jetty Secured With Elytron</title></head>
  <body>
    <h2>Embedded Jetty Server Secured Using Elytron</h2>
    <p><font size="5" color="blue">Hello alice! You've authenticated successfully using Elytron!</font></p>
  </body>
</html>
* Connection #0 to host localhost left intact
```
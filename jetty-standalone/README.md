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
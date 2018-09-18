### Securing an embedded Jetty server using Elytron

1. Take a look at the ```org.wildfly.security.examples.HelloWorld``` class that starts an embedded Jetty server,
creates an Elytron map-backed security realm, and adds the configuration necessary to secure the embedded Jetty server
using Elytron. Notice that the created security realm has two users, ```alice``` and ```bob```, with passwords ```alice123+```
and ```bob123+```, respectively. Also notice that alice has both the ```employee``` and ```admin``` roles but bob only has
the ```employee``` role.


2. Build and run the application:

```
mvn clean install exec:exec
```

3. First attempt to access the application as ```bob```. Since accessing the application requires ```admin``` role, you'll
see an HTTP 403 error. Next, attempt to access the application as ```alice```. Since ```alice``` has ```admin``` role,
you'll be able to successfully log in.

```
http://localhost:8080/secured
```
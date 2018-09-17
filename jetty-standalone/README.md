### Securing an embedded Jetty server using Elytron

1. Take a look at the ```configure-elytron.cli``` file that creates an Elytron filesystem-based security realm and adds the configuration necessary to secure our application using Elytron. Notice that our security realms has two users, alice and bob, with passwords alice123+ and bob123+, respectively. Also notice that alice has both the "employee" and "admin" roles but bob only has the "employee" role.

```
$WILDFLY_HOME/bin/jboss-cli.sh --connect --file=configure-elytron.cli
```

2. Build and run the application:

```
mvn clean install exec:exec
```

3. First access the application as bob. Then access the application as alice.

```
http://localhost:8080/secured
```
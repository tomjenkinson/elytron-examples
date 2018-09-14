/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.examples;

import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.io.IOException;
import java.security.Provider;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.authentication.BasicAuthenticator;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.util.log.AbstractLogger;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.StdErrLog;
import org.eclipse.jetty.util.security.Constraint;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.http.HttpAuthenticator;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.util.FilterServerMechanismFactory;
import org.wildfly.security.http.util.SecurityProviderServerMechanismFactory;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

public class HelloWorld {

    private static final WildFlyElytronProvider elytronProvider = new WildFlyElytronProvider();

    public static void main(String[] args) throws Exception {
        StdErrLog logger = new StdErrLog();
        logger.setDebugEnabled(true);
        logger.setLevel(AbstractLogger.LEVEL_ALL);
        Log.setLog(logger);

        System.err.println("************ SETTING UP");

        final SecurityDomain securityDomain = createSecurityDomain();
        Server server = new Server();
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(8080);
        server.setConnectors(new Connector[] {connector});

        LoginService loginService = new HashLoginService("MyRealm",
                "src/test/resources/realm.properties");
        server.addBean(loginService);

        //ServletHandler servletHandler = new ServletHandler();
        //server.setHandler(servletHandler);
        ConstraintSecurityHandler security = new ConstraintSecurityHandler();
        server.setHandler(security);


        Constraint constraint = new Constraint();
        constraint.setName("auth");
        constraint.setAuthenticate(true);
        constraint.setRoles(new String[] { "user", "admin" });

        ConstraintMapping mapping = new ConstraintMapping();
        mapping.setPathSpec("/status");
        mapping.setConstraint(constraint);

        security.setConstraintMappings(Collections.singletonList(mapping));
        //security.setAuthenticator(new BasicAuthenticator());
        security.setAuthenticatorFactory(new ElytronAuthenticatorFactory(createSecurityDomain()));
        security.setLoginService(loginService);


        ServletHandler servletHandler = new ServletHandler();
        servletHandler.addServletWithMapping(BlockingServlet.class, "/status");
        security.setHandler(servletHandler);
        server.start();

    }

    private static SecurityDomain createSecurityDomain() throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR, elytronProvider);

        Map<String, SimpleRealmEntry> passwordMap = new HashMap<>();
        passwordMap.put("elytron", new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec("secret".toCharArray()))))));

        SimpleMapBackedSecurityRealm simpleRealm = new SimpleMapBackedSecurityRealm(() -> new Provider[] { elytronProvider });
        MapAttributes attributes = new MapAttributes();
        HashSet<String> elytronRoles = new HashSet<>();
        elytronRoles.add("user");
        elytronRoles.add("admin");
        attributes.addAll(RoleDecoder.KEY_ROLES, elytronRoles);
        Map<String, SimpleRealmEntry> identityMap = new HashMap<>();
        identityMap.put("elytron",
                new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec("secret".toCharArray())))), attributes));
        identityMap.put("bob",
                new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec("secret".toCharArray()))))));
        simpleRealm.setIdentityMap(identityMap);
        //simpleRealm.setPasswordMap(passwordMap);

        SecurityDomain.Builder builder = SecurityDomain.builder()
                .setDefaultRealmName("TestRealm");

        builder.addRealm("TestRealm", simpleRealm).build();
        builder.setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()));
        //builder.setRoleMapper(RoleMapper.constant())

        return builder.build();
    }



    private static HttpAuthenticationFactory createHttpAuthenticationFactory(final SecurityDomain securityDomain) {
        HttpServerAuthenticationMechanismFactory providerFactory = new SecurityProviderServerMechanismFactory(() -> new Provider[] {elytronProvider});
        HttpServerAuthenticationMechanismFactory httpServerMechanismFactory = new FilterServerMechanismFactory(providerFactory, true, "BASIC");

        return HttpAuthenticationFactory.builder()
                .setSecurityDomain(securityDomain)
                .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(
                        MechanismConfiguration.builder()
                                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                .build()))
                .setFactory(httpServerMechanismFactory)
                .build();
    }

    /*private static HttpHandler wrap(final HttpHandler toWrap, final SecurityDomain securityDomain) {
        HttpAuthenticationFactory httpAuthenticationFactory = createHttpAuthenticationFactory(securityDomain);

        HttpHandler rootHandler = new ElytronRunAsHandler(toWrap);

        //
         // In this example we know the ElytronRunAsHandler is calling a single handler that is not going to switch to blocking,
         // as the ElytronRunAsHandler is associating the identity with a ThreadLocal if it was possible the handler could switch
         // from non-blocking to blocking we would insert the BlockingHandler here.
         //

        rootHandler = new AuthenticationCallHandler(rootHandler);
        rootHandler = new AuthenticationConstraintHandler(rootHandler);

        return ElytronContextAssociationHandler.builder()
                .setNext(rootHandler)
                .setMechanismSupplier(() -> {
                    try {
                        return Collections.singletonList(httpAuthenticationFactory.createMechanism("BASIC"));
                    } catch (HttpAuthenticationException e) {
                        throw new RuntimeException(e);
                    }
        }).build();
    }*/

    public static class BlockingServlet extends HttpServlet {

        protected void doGet(
                HttpServletRequest request,
                HttpServletResponse response)
                throws ServletException, IOException {

            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("{ \"status\": \"ok\"}");
        }
    }

    /**
     * SIMPLE JETTY AUTHENTICATION, ACCESS http://localhost:8080/status using user:password
     */
    /*public static void main(String[] args) throws Exception {
    https://www.eclipse.org/jetty/documentation/9.4.x/embedded-examples.html
        final SecurityDomain securityDomain = createSecurityDomain();
        Server server = new Server();
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(8080);
        server.setConnectors(new Connector[] {connector});

        LoginService loginService = new HashLoginService("MyRealm",
                "src/test/resources/realm.properties");
        server.addBean(loginService);

        //ServletHandler servletHandler = new ServletHandler();
        //server.setHandler(servletHandler);
        ConstraintSecurityHandler security = new ConstraintSecurityHandler();
        server.setHandler(security);


        Constraint constraint = new Constraint();
        constraint.setName("auth");
        constraint.setAuthenticate(true);
        constraint.setRoles(new String[] { "user", "admin" });

        ConstraintMapping mapping = new ConstraintMapping();
        mapping.setPathSpec("/status");
        mapping.setConstraint(constraint);

        security.setConstraintMappings(Collections.singletonList(mapping));
        security.setAuthenticator(new BasicAuthenticator());
        security.setLoginService(loginService);


        ServletHandler servletHandler = new ServletHandler();
        servletHandler.addServletWithMapping(BlockingServlet.class, "/status");
        security.setHandler(servletHandler);
        server.start();

    }*/

}

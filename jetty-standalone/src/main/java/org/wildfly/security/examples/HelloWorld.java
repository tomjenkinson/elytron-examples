/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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
import java.io.PrintWriter;
import java.security.Provider;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.HandlerWrapper;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.util.security.Constraint;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.examples.ElytronHttpExchange.ElytronUserAuthentication;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

public class HelloWorld {

    private static final WildFlyElytronProvider elytronProvider = new WildFlyElytronProvider();
    private static SecurityDomain securityDomain;

    public static void main(String[] args) throws Exception {
        // Create the Jetty server instance
        Server server = new Server(8080);

        ConstraintSecurityHandler security = new ConstraintSecurityHandler();
        server.setHandler(security);

        // Create a constraint that specifies that accessing "/secured" requires authentication
        // and the authenticated user must have "admin" role
        Constraint constraint = new Constraint();
        constraint.setName("auth");
        constraint.setAuthenticate(true);
        constraint.setRoles(new String[] { "admin" });
        ConstraintMapping mapping = new ConstraintMapping();
        mapping.setPathSpec("/secured");
        mapping.setConstraint(constraint);
        security.setConstraintMappings(Collections.singletonList(mapping));

        // Specify that authentication should be handled by ElytronAuthenticator
        securityDomain = createSecurityDomain();
        security.setAuthenticator(new ElytronAuthenticator(securityDomain));

        HandlerWrapper wrapper = new HandlerWrapper()
        {
            @Override
            public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
                Authentication authentication = baseRequest.getAuthentication();
                SecurityIdentity securityIdentity = (authentication instanceof ElytronUserAuthentication) ? ((ElytronUserAuthentication) authentication).getSecurityIdentity() : null;
                if (securityIdentity != null) {
                    try {
                        securityIdentity.runAs((Callable<Void>) () -> {
                            super.handle(target, baseRequest, request, response);
                            return null;
                        });
                    } catch (Exception e) {
                        throw new ServletException(e);
                    }
                } else {
                    super.handle(target,baseRequest,request,response);
                }
            }
        };

        ServletHandler servletHandler = new ServletHandler();
        wrapper.setHandler(servletHandler);
        servletHandler.addServletWithMapping(SecuredServlet.class, "/secured");
        security.setHandler(wrapper);
        server.start();

    }

    private static SecurityDomain createSecurityDomain() throws Exception {
        // Create an Elytron map-backed security realm
        SimpleMapBackedSecurityRealm simpleRealm = new SimpleMapBackedSecurityRealm(() -> new Provider[] { elytronProvider });
        Map<String, SimpleRealmEntry> identityMap = new HashMap<>();

        // Add user alice
        identityMap.put("alice", new SimpleRealmEntry(getCredentialsForClearPassword("alice123+"), getAttributesForRoles("employee", "admin")));

        // Add user bob
        identityMap.put("bob", new SimpleRealmEntry(getCredentialsForClearPassword("bob123+"), getAttributesForRoles("employee")));
        simpleRealm.setIdentityMap(identityMap);

        // Add the map-backed security realm to a new security domain's list of realms
        SecurityDomain.Builder builder = SecurityDomain.builder()
                .addRealm("ExampleRealm", simpleRealm).build()
                .setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()))
                .setDefaultRealmName("ExampleRealm");

        return builder.build();
    }

    public static class SecuredServlet extends HttpServlet {

        protected void doGet(
                HttpServletRequest request,
                HttpServletResponse response)
                throws ServletException, IOException {

            response.setContentType("text/html");
            response.setStatus(HttpServletResponse.SC_OK);
            PrintWriter writer = response.getWriter();
            writer.println("<html>");
            writer.println("  <head><title>Embedded Jetty Secured With Elytron</title></head>");
            writer.println("  <body>");
            writer.println("    <h2>Embedded Jetty Server Secured Using Elytron</h2>");
            writer.println("    <p><font size=\"5\" color=\"blue\">Hello " + securityDomain.getCurrentSecurityIdentity().getPrincipal().getName() + "! You've authenticated successfully using Elytron!" + "</font></p>");
            writer.println("  </body>");
            writer.println("</html>");
        }
    }

    private static List<Credential> getCredentialsForClearPassword(String clearPassword) throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR, elytronProvider);
        return Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(clearPassword.toCharArray()))));
    }

    private static MapAttributes getAttributesForRoles(String... roles) {
        MapAttributes attributes = new MapAttributes();
        HashSet<String> rolesSet = new HashSet<>();
        if (roles != null) {
            for (String role : roles) {
                rolesSet.add(role);
            }
        }
        attributes.addAll(RoleDecoder.KEY_ROLES, rolesSet);
        return attributes;
    }

}

package org.wildfly.security.examples;

import org.eclipse.jetty.http.HttpCookie;
import org.eclipse.jetty.security.DefaultUserIdentity;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.UserIdentity;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.Scope;

import javax.security.auth.Subject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronHttpExchange implements HttpExchangeSpi {

    private final Request request;
    private final Response response;

    public ElytronHttpExchange(Request request, Response response) {
        this.request = request;
        this.response = response;
    }

    @Override
    public List<String> getRequestHeaderValues(String headerName) {
        Enumeration<String> headerEnum = this.request.getHeaders(headerName);

        if (headerEnum == null) {
            return Collections.emptyList();
        }

        List<String> values = new ArrayList<>();

        while (headerEnum.hasMoreElements()) {
            values.add(headerEnum.nextElement());
        }

        return Collections.unmodifiableList(values);
    }

    @Override
    public void addResponseHeader(String headerName, String headerValue) {
        this.response.addHeader(headerName, headerValue);
    }


    @Override
    public void setStatusCode(int statusCode) {
        response.setStatus(statusCode);
    }

    @Override
    public void authenticationComplete(SecurityIdentity securityIdentity, String mechanismName) {
        Subject subject = new Subject();
        Principal principal = securityIdentity.getPrincipal();
        Roles roles = securityIdentity.getRoles();
        ArrayList<String> rolesList = new ArrayList<>();
        roles.spliterator().forEachRemaining(rolesList::add);

        this.request.setAuthentication(new ElytronUserAuthentication(this.request.getAuthType(), new DefaultUserIdentity(subject, principal, rolesList.toArray(new String[rolesList.size()])), securityIdentity));
    }

    @Override
    public void authenticationFailed(String message, String mechanismName) {

    }

    @Override
    public void badRequest(HttpAuthenticationException error, String mechanismName) {

    }

    @Override
    public String getRequestMethod() {
        return this.request.getMethod();
    }

    @Override
    public URI getRequestURI() {
        try {
            return request.getHttpURI().toURI();
        } catch (URISyntaxException e) {
            return null;
        }
    }

    @Override
    public String getRequestPath() {
        return request.getHttpURI().getPath();
    }

    @Override
    public Map<String, List<String>> getRequestParameters() {
        Map<String, String[]> requestParameters = request.getParameterMap();
        if (requestParameters == null) {
            return null;
        }
        Map<String, List<String>> convertedRequestParameters = new HashMap<>(requestParameters.size());
        for (String parameter : requestParameters.keySet()) {
            convertedRequestParameters.put(parameter, Arrays.asList(requestParameters.get(parameter)));
        }
        return convertedRequestParameters;
    }

    @Override
    public List<HttpServerCookie> getCookies() {
        List<HttpServerCookie> cookies = Stream.of(this.request.getCookies()).map(new Function<javax.servlet.http.Cookie, HttpServerCookie>() {
            @Override
            public HttpServerCookie apply(javax.servlet.http.Cookie cookie) {
                return new HttpServerCookie() {
                    @Override
                    public String getName() {
                        return cookie.getName();
                    }

                    @Override
                    public String getValue() {
                        return cookie.getValue();
                    }

                    @Override
                    public String getDomain() {
                        return cookie.getDomain();
                    }

                    @Override
                    public int getMaxAge() {
                        return cookie.getMaxAge();
                    }

                    @Override
                    public String getPath() {
                        return cookie.getPath();
                    }

                    @Override
                    public boolean isSecure() {
                        return cookie.getSecure();
                    }

                    @Override
                    public int getVersion() {
                        return cookie.getVersion();
                    }

                    @Override
                    public boolean isHttpOnly() {
                        return cookie.isHttpOnly();
                    }
                };
            }
        }).collect(Collectors.toList());

        return cookies;
    }

    @Override
    public InputStream getRequestInputStream() {
        try {
            return request.getInputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public OutputStream getResponseOutputStream() {
        try {
            return response.getOutputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public InetSocketAddress getSourceAddress() {
        return this.request.getRemoteInetSocketAddress();
    }

    @Override
    public void setResponseCookie(HttpServerCookie cookie) {
        this.response.addCookie(new HttpCookie(cookie.getName(), cookie.getValue(), cookie.getDomain(), cookie.getPath(), cookie.getMaxAge(), cookie.isHttpOnly(), cookie.isSecure(), null, cookie.getVersion()));
    }

    @Override
    public HttpScope getScope(Scope scope) {
        return null;
    }

    @Override
    public Collection<String> getScopeIds(Scope scope) {
        return null;
    }

    @Override
    public HttpScope getScope(Scope scope, String id) {
        return null;
    }

    class ElytronUserAuthentication extends UserAuthentication {
        private final SecurityIdentity securityIdentity;

        public ElytronUserAuthentication(String method, UserIdentity userIdentity, SecurityIdentity securityIdentity) {
            super(method, userIdentity);
            this.securityIdentity = securityIdentity;
        }


        @Override
        public void logout() {
        }

        public SecurityIdentity getSecurityIdentity() {
            return securityIdentity;
        }
    }
}
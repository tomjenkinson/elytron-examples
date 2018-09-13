package org.wildfly.security.examples;

import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.security.Constraint;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpAuthenticator;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.List;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronAuthenticatorWrapper implements Authenticator {

    private final AuthConfiguration configuration;
    private final Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier;
    private final SecurityDomain securityDomain;

    public ElytronAuthenticatorWrapper(AuthConfiguration configuration, Supplier<List<HttpServerAuthenticationMechanism>> mechanismSupplier, SecurityDomain securityDomain) {
        this.configuration = configuration;
        this.mechanismSupplier = mechanismSupplier;
        this.securityDomain = securityDomain;
    }

    @Override
    public void setConfiguration(AuthConfiguration configuration) {
        // no-op
    }

    @Override
    public String getAuthMethod() {
        //return this.configuration.getAuthMethod();
        return Constraint.__BASIC_AUTH;
    }

    @Override
    public void prepareRequest(ServletRequest request) {
        // no-op
    }

    @Override
    public Authentication validateRequest(ServletRequest servletRequest, ServletResponse servletResponse, boolean mandatory) throws ServerAuthException {
        System.out.println("*************** VALIDATING REQUEST");
        Request request = (Request) servletRequest;
        Response response = (Response) servletResponse;
        HttpAuthenticator authenticator = HttpAuthenticator.builder()
                .setSecurityDomain(securityDomain)
                .setMechanismSupplier(mechanismSupplier)
                .setHttpExchangeSpi(new ElytronHttpExchange(request, response))
                .setRequired(mandatory)
                .setIgnoreOptionalFailures(false) // TODO - Cover this one later.
                .build();

        try {
            System.err.println("**** ATTEMPTING TO AUTHENTICATE");
            authenticator.authenticate();
        } catch (HttpAuthenticationException e) {
            throw new ServerAuthException(e);
        }

        return request.getAuthentication();
    }

    @Override
    public boolean secureResponse(ServletRequest request, ServletResponse response, boolean mandatory, Authentication.User validatedUser) throws ServerAuthException {
        return true;
    }
}
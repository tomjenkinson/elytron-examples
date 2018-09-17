package org.wildfly.security.examples;

import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.security.Constraint;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpAuthenticator;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.util.FilterServerMechanismFactory;
import org.wildfly.security.http.util.SecurityProviderServerMechanismFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import java.security.Provider;
import java.util.stream.Collectors;

public class ElytronAuthenticator implements Authenticator {

    private final SecurityDomain securityDomain;
    private final HttpAuthenticationFactory httpAuthenticationFactory;

    public ElytronAuthenticator(SecurityDomain securityDomain) {
        this.securityDomain = securityDomain;
        //HttpServerAuthenticationMechanismFactory providerFactory = new SecurityProviderServerMechanismFactory(() -> new Provider[] {new WildFlyElytronProvider()});
        HttpServerAuthenticationMechanismFactory httpServerMechanismFactory = new CustomMechanismFactory();

        httpAuthenticationFactory = HttpAuthenticationFactory.builder()
                .setSecurityDomain(securityDomain)
                .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(
                        MechanismConfiguration.builder()
                                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                .build()))
                .setFactory(httpServerMechanismFactory)
                .build();
    }

    @Override
    public void setConfiguration(AuthConfiguration configuration) {
        // no-op
    }

    @Override
    public String getAuthMethod() {
        return CustomMechanismFactory.CUSTOM_NAME;
    }

    @Override
    public void prepareRequest(ServletRequest request) {
        // no-op
    }

    @Override
    public Authentication validateRequest(ServletRequest servletRequest, ServletResponse servletResponse, boolean mandatory) throws ServerAuthException {
        Request request = (Request) servletRequest;
        Response response = (Response) servletResponse;
        HttpAuthenticator authenticator = HttpAuthenticator.builder()
                .setSecurityDomain(securityDomain)
                .setMechanismSupplier(() -> httpAuthenticationFactory.getMechanismNames().stream()
                        .map(mechanismName -> {
                            try {
                                return httpAuthenticationFactory.createMechanism(mechanismName);
                            } catch (HttpAuthenticationException e) {
                                throw new RuntimeException("Failed to create mechanism.", e);
                            }
                        })
                        .filter(m -> m != null)
                        .collect(Collectors.toList()))
                .setHttpExchangeSpi(new ElytronHttpExchange(request, response))
                .setRequired(mandatory)
                .build();

        boolean authenticated;
        try {
            authenticated = authenticator.authenticate();
        } catch (HttpAuthenticationException e) {
            throw new ServerAuthException(e);
        }
        if (authenticated) {
            return request.getAuthentication();
        } else {
            return Authentication.SEND_CONTINUE;
        }
    }

    @Override
    public boolean secureResponse(ServletRequest request, ServletResponse response, boolean mandatory, Authentication.User validatedUser) throws ServerAuthException {
        return true;
    }
}
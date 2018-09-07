/*
* Copyright 2018 Red Hat, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package org.wildfly.security.examples;

import static org.wildfly.security.examples.CustomMechanismFactory.CUSTOM_NAME;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;

class CustomHeaderHttpAuthenticationMechanism implements HttpServerAuthenticationMechanism {



    private static final HttpServerMechanismsResponder RESPONDER = new HttpServerMechanismsResponder() {
        public void sendResponse(HttpServerResponse response) throws HttpAuthenticationException {
            response.addResponseHeader("CUSTOM-MESSAGE", "Please resubmit the request with a username" +
                    " specified using the CUSTOM-USERNAME header and a password specified using the CUSTOM-PASSWORD header.");
            response.setStatusCode(401);
        }
    };

    private final CallbackHandler callbackHandler;

    CustomHeaderHttpAuthenticationMechanism(final CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        final String username = request.getFirstRequestHeaderValue("CUSTOM-USERNAME");
        final String password = request.getFirstRequestHeaderValue("CUSTOM-PASSWORD");

        if (username == null || username.length() == 0 || password == null || password.length() == 0) {
            request.noAuthenticationInProgress(RESPONDER);
            return;
        }

        // Authenticate the user using the provided username and password
        NameCallback nameCallback = new NameCallback("Remote Authentication Name", username);
        nameCallback.setName(username);
        final PasswordGuessEvidence evidence = new PasswordGuessEvidence(password.toCharArray());
        EvidenceVerifyCallback evidenceVerifyCallback = new EvidenceVerifyCallback(evidence);

        try {
            callbackHandler.handle(new Callback[] { nameCallback, evidenceVerifyCallback });
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }

        if (! evidenceVerifyCallback.isVerified()) {
            request.authenticationFailed("Username / Password Validation Failed", RESPONDER);
        }

        // Check that the authenticated user is allowed to login
        AuthorizeCallback authorizeCallback = new AuthorizeCallback(username, username);

        try {
            callbackHandler.handle(new Callback[] {authorizeCallback});
            if (authorizeCallback.isAuthorized()) {
                callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.SUCCEEDED });
                request.authenticationComplete();
            } else {
                callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.FAILED });
                request.authenticationFailed("Authorization check failed.", RESPONDER);
            }
        } catch (IOException | UnsupportedCallbackException e) {
            throw new HttpAuthenticationException(e);
        }
    }

    public String getMechanismName() {
        return CUSTOM_NAME;
    }

}

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

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

public class CustomMechanismFactory implements HttpServerAuthenticationMechanismFactory {

    static final String CUSTOM_NAME = "CUSTOM_MECHANISM";

    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String name, Map<String, ?> properties,
                                                                           CallbackHandler handler) throws HttpAuthenticationException {
        if (CUSTOM_NAME.equals(name)) {
            return new CustomHeaderHttpAuthenticationMechanism(handler);
        }

        return null;
    }

    public String[] getMechanismNames(Map<String, ?> properties) {
        return new String[] { CUSTOM_NAME };
    }

}
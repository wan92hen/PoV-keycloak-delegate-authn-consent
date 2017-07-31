/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.examples.authentication.authenticators.browser;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class DelegateAuthnConsentAuthenticatorFactory implements AuthenticatorFactory {
    protected static final String DEFAULT_PROVIDER = "authnConsentIdentityProvider";
    
    // NOTES: at first, try to use MultivaluedString by modifying theme/base/admin/resources/templetes/kc-provider-config.html but can not be reflected to admin console UI...
    
    private static final String FW_QUERY_PARAMS_BASE = "forwarding.query.parameters";
    private static final String FW_QUERY_PARAMS_LABEL = "Query Parameters to be forwarded to External IdP";
    private static final String FW_QUERY_PARAMS_HELP = FW_QUERY_PARAMS_LABEL;
    private static final int FW_QUERY_PARAMS_MAX = 5;
    private static final String FW_HTTP_HEADERS_BASE = "forwarding.http.headers";    
    private static final String FW_HTTP_HEADERS_LABEL = "HTTP Header Fields to be forwarded to External IdP";
    private static final String FW_HTTP_HEADERS_HELP = FW_HTTP_HEADERS_LABEL;
    private static final int FW_HTTP_HEADERS_MAX = 5;

    private static List<String> FW_QUERY_PARAMS = new ArrayList<>(FW_QUERY_PARAMS_MAX);
    private static List<String> FW_HTTP_HEADERS = new ArrayList<>(FW_HTTP_HEADERS_MAX);
    
    protected static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.ALTERNATIVE, AuthenticationExecutionModel.Requirement.DISABLED
    };
    
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        configProperties.add(new ProviderConfigProperty(DEFAULT_PROVIDER, "Default Delegating Authentication and Consent Identity Provider", 
                "To automatically redirect to an identity provider set to the alias of the delegating authentication and consent identity provider.", 
                ProviderConfigProperty.STRING_TYPE, null));

        for(int i = 1; i <= FW_QUERY_PARAMS_MAX; i++) {
            String name = FW_QUERY_PARAMS_BASE + "." + i;
            FW_QUERY_PARAMS.add(name);
            configProperties.add(new ProviderConfigProperty(name, FW_QUERY_PARAMS_LABEL + " #" + i, FW_QUERY_PARAMS_HELP + " #" + i, ProviderConfigProperty.STRING_TYPE, null));
        }
        for(int i = 1; i <= FW_HTTP_HEADERS_MAX; i++) {
            String name = FW_HTTP_HEADERS_BASE + "." + i;
            FW_HTTP_HEADERS.add(name);
            configProperties.add(new ProviderConfigProperty(name, FW_HTTP_HEADERS_LABEL + " #" + i, FW_HTTP_HEADERS_HELP + " #" + i, ProviderConfigProperty.STRING_TYPE, null));        
        }
    }
    
    static List<String> getQueryParameterNameList() {
        return FW_QUERY_PARAMS;
    }
    
    static List<String> getHttpHeaderNameList() {
        return FW_HTTP_HEADERS;
    }
    
    @Override
    public String getDisplayType() {
        return "Delegating Authenticatoin and Consent Identity Provider Redirector";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getHelpText() {
        return "Redirects to default Delegating Authentication and Consent Identity Provider";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {      
        return configProperties;
        //return Collections.singletonList(rep);
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new DelegateAuthnConsentAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "delegate-authn-consent-idp-redirect";
    }

}

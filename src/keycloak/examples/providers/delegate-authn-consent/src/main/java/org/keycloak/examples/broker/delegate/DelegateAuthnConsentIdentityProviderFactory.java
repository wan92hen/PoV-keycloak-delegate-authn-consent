package org.keycloak.examples.broker.delegate;

import java.io.InputStream;
import java.util.Map;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class DelegateAuthnConsentIdentityProviderFactory extends AbstractIdentityProviderFactory<DelegateAuthnConsentIdentityProvider> {

    public static final String PROVIDER_ID = "delegate-authn-consent";

    @Override
    public String getName() {
        return "Delegating Authentication and Consent";
    }

    @Override
    public DelegateAuthnConsentIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new DelegateAuthnConsentIdentityProvider(session, new DelegateAuthnConsentIdentityProviderConfig(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, InputStream inputStream) {
        return null;
    }

}

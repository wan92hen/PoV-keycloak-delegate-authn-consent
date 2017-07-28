package org.keycloak.examples.broker.delegate;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class DelegateAuthnIdentityProviderFactory extends AbstractIdentityProviderFactory<DelegateAuthnIdentityProvider<DelegateAuthnIdentityProviderConfig>> {

    public static final String PROVIDER_ID = "delegate-authn";

    @Override
    public String getName() {
        return "Delegating Authentication";
    }

    @Override
    public DelegateAuthnIdentityProvider<DelegateAuthnIdentityProviderConfig> create(KeycloakSession session, IdentityProviderModel model) {
        return new DelegateAuthnIdentityProvider<DelegateAuthnIdentityProviderConfig>(session, new DelegateAuthnIdentityProviderConfig(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}

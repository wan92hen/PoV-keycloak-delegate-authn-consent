package org.keycloak.examples.broker.delegate;

import org.keycloak.models.IdentityProviderModel;

public class DelegateAuthnConsentIdentityProviderConfig extends DelegateAuthnIdentityProviderConfig {

    private static final long serialVersionUID = 1L;

    public DelegateAuthnConsentIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public boolean isFormPostSelected() {
        return Boolean.valueOf(getConfig().get("formPostSelected"));
    }

    public void setFormPostSelected(boolean formPostSelected) {
        getConfig().put("formPostSelected", String.valueOf(formPostSelected));
    }    
}


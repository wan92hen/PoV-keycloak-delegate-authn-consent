package org.keycloak.examples.broker.delegate;

import org.keycloak.models.IdentityProviderModel;

public class DelegateAuthnIdentityProviderConfig extends IdentityProviderModel {

	private static final long serialVersionUID = 1L;

	public DelegateAuthnIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public String getAuthenticationUri() {
        return getConfig().get("authenticationUri");
    }

    public void setAuthenticationUri(String authenticationUri) {
        getConfig().put("authenticationUri", authenticationUri);
    }

    public String getUserinfoEndpoint() {
        return getConfig().get("userinfoEndpoint");
    }

    public void setUserinfoEndpoint(String userinfoEndpoint) {
        getConfig().put("userinfoEndpoint", userinfoEndpoint);
    }
    
    public String getClientId() {
        return getConfig().get("clientId");
    }

    public void setClientId(String clientId) {
        getConfig().put("clientId", clientId);
    }

    public String getClientSecret() {
        return getConfig().get("clientSecret");
    }

    public void setClientSecret(String clientSecret) {
        getConfig().put("clientSecret", clientSecret);
    }
}


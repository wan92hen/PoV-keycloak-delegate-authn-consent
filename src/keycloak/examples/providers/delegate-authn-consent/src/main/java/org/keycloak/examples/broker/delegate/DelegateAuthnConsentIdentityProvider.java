package org.keycloak.examples.broker.delegate;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
//import org.keycloak.examples.broker.custom.CustomProtocolIdentityProviderConfig;
import org.keycloak.models.KeycloakSession;

public class DelegateAuthnConsentIdentityProvider extends DelegateAuthnIdentityProvider<DelegateAuthnConsentIdentityProviderConfig>  {
	protected static final Logger logger = Logger.getLogger(DelegateAuthnConsentIdentityProvider.class);

    // NOTE : need to use the same prefix in both Custom Identity Provider Authentication Provider and Custom Broker Provider
	protected static final String FWD_PREFIX = "fwd_";
	
	public DelegateAuthnConsentIdentityProvider(KeycloakSession session, DelegateAuthnConsentIdentityProviderConfig config) {
		super(session, config);
	}  
    
    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            if (getConfig().isFormPostSelected()) {
            	return Response.ok().type(MediaType.TEXT_HTML_TYPE).entity(getPostBindBody(request)).build();
            } else {
            	URI authenticationUrl = createAuthenticationUrl(request).build();
            	return Response.seeOther(authenticationUrl).build();
            }
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication and consent request to External IdP.", e);
        }    
    }

	@Override
	protected UriBuilder createAuthenticationUrl(AuthenticationRequest request) {
		// TODO : base64urlencode for query parameters
    	UriBuilder builder = UriBuilder.fromUri(getConfig().getAuthenticationUri())
                .queryParam(DelegateAuthnIdentityProvider.PROVIDER_PARAMETER_STATE, request.getState().getEncodedState())
                .queryParam(DelegateAuthnIdentityProvider.PROVIDER_PARAMETER_REDIRECT_URI, request.getRedirectUri());
    	List<String> paramNames = getForwardedParameterKeys(request.getAuthenticationSession().getClientNotes());
    	if (!paramNames.isEmpty()) {
    		for (String name : paramNames) {
    			String value = request.getAuthenticationSession().getClientNote(name);
    			if (value != null) builder.queryParam(name, value);
    		}
    	}
    	return builder;
    }
	
	protected List<String> getForwardedParameterKeys(Map<String, String> map) {
    	List<String> paramKeys = new ArrayList<String>();
    	for (String key : map.keySet()) {
    		if (key.startsWith(FWD_PREFIX)) paramKeys.add(key);
    	}  	
    	return paramKeys;
    }   
	
	protected String getPostBindBody(AuthenticationRequest request) {
        
        StringBuilder builder = new StringBuilder();
        
        builder.append("<HTML>");
        builder.append("<HEAD>");
        builder.append("<TITLE>Submit This Form</TITLE>");
        builder.append("</HEAD>");
        builder.append("<BODY Onload=\"javascript:document.forms[0].submit()\">");
        builder.append("<FORM METHOD=\"POST\" ACTION=\"" + getConfig().getAuthenticationUri() + "\">");       
        builder.append("<INPUT name=\"state\" TYPE=\"HIDDEN\" VALUE=\"" + request.getState().getEncodedState() + "\" />");
        builder.append("<INPUT name=\"redirect_uri\" TYPE=\"HIDDEN\" VALUE=\"" + request.getRedirectUri() + "\" />");

    	List<String> paramNames = getForwardedParameterKeys(request.getAuthenticationSession().getClientNotes());
    	if (!paramNames.isEmpty()) {
    		for (String name : paramNames) {
    			String value = request.getAuthenticationSession().getClientNote(name);
    			if (value != null) builder.append("<INPUT name=\"" + name + "\" TYPE=\"HIDDEN\" VALUE=\"" + value+ "\" />");
    		}
    	} 
              
        builder.append("<NOSCRIPT>")
        .append("<P>JavaScript is disabled. We strongly recommend to enable it. Click the button below to continue.</P>")
        .append("<INPUT TYPE=\"SUBMIT\" VALUE=\"CONTINUE\" />")
        .append("</NOSCRIPT>");
        builder.append("</FORM></BODY></HTML>");
        return builder.toString();
    }   

}

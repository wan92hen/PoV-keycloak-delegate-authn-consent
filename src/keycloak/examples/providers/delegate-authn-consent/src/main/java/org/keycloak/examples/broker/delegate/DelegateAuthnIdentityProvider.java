package org.keycloak.examples.broker.delegate;

import java.net.URI;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.oidc.util.JsonSimpleHttp;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Base64;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;

import com.fasterxml.jackson.databind.JsonNode;

public class DelegateAuthnIdentityProvider<C extends DelegateAuthnIdentityProviderConfig> extends AbstractIdentityProvider<C> {
    protected static final Logger logger = Logger.getLogger(DelegateAuthnIdentityProvider.class);
    
    // Notes: the following literals also must be used by the external IdP (namely part of this custom protocol)
    protected static final String ACCESS_DENIED = "access_denied";
    protected static final String PROVIDER_PARAMETER_ASSERTION_REFERENCE = "artifact";
    protected static final String PROVIDER_PARAMETER_STATE = "state";
    protected static final String PROVIDER_PARAMETER_ERROR = "error";    
    protected static final String PROVIDER_PARAMETER_REDIRECT_URI = "redirect_uri";    
    protected static final String PROVIDER_PARAMETER_USERID = "userid";    
    protected static final String PROVIDER_PARAMETER_USERNAME = "username";        

    public DelegateAuthnIdentityProvider(KeycloakSession session, C config) {
        super(session, config);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event);
    }
    
    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            URI authenticationUrl = createAuthenticationUrl(request).build();
            // Response.temporaryRedirect(authenticationUrl).build() should be used,
            // but most browsers seem to support this status code (307) so that deprecated 302 state code is used.
            return Response.status(302).location(authenticationUrl).build();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication request to External IdP.", e);
        }        
    }
    
    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.ok(identity.getToken()).build();
    }
    
    protected BrokeredIdentityContext getFederatedIdentity(String artifact) {
        try {
            String authHeader = "Basic " + encodeCredentials(getConfig().getClientId(), getConfig().getClientSecret());
            JsonNode profile = JsonSimpleHttp.asJson(SimpleHttp.doPost(getConfig().getUserinfoEndpoint(), session)
                    .param(PROVIDER_PARAMETER_ASSERTION_REFERENCE, artifact)
                    .header(HttpHeaders.AUTHORIZATION, authHeader));
            
            String userId = getJsonProperty(profile, PROVIDER_PARAMETER_USERID);
            BrokeredIdentityContext user = new BrokeredIdentityContext(userId);
            
            if (getConfig().isStoreToken()) {
                user.setToken(profile.toString());
            }
            
            // BrokeredIdentityContext's id(constructor) and username MUST NOT be null.
            user.setUsername(getJsonProperty(profile, PROVIDER_PARAMETER_USERNAME)); 
            user.setIdpConfig(getConfig());
            user.setIdp(this);

            AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
            
            return user;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not fetch attributes from External IdP's userinfo endpoint.", e);
        }
    }
    
    private String encodeCredentials(String username, String password) {
        String text = username + ":" + password;
        return (Base64.encodeBytes(text.getBytes()));
    }

    /**
     * Get JSON property as text. JSON numbers and booleans are converted to text. Empty string is converted to null. 
     * 
     * @param jsonNode to get property from
     * @param name of property to get
     * @return string value of the property or null.
     */
    protected String getJsonProperty(JsonNode jsonNode, String name) {
        if (jsonNode.has(name) && !jsonNode.get(name).isNull()) {
              String s = jsonNode.get(name).asText();
              if(s != null && !s.isEmpty())
                      return s;
              else
                        return null;
        }
        return null;
    }

    protected UriBuilder createAuthenticationUrl(AuthenticationRequest request) {
        UriBuilder builder = UriBuilder.fromUri(getConfig().getAuthenticationUri())
                .queryParam(PROVIDER_PARAMETER_STATE, request.getState().getEncodedState())
                .queryParam(PROVIDER_PARAMETER_REDIRECT_URI, request.getRedirectUri());
        return builder;
    }
    
    protected class Endpoint {
        protected AuthenticationCallback callback;
        protected RealmModel realm;
        protected EventBuilder event;

        @Context
        protected KeycloakSession session;

        @Context
        protected ClientConnection clientConnection;

        @Context
        protected HttpHeaders headers;

        @Context
        protected UriInfo uriInfo;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            this.callback = callback;
            this.realm = realm;
            this.event = event;
        }

        @GET
        public Response authResponse(@QueryParam(PROVIDER_PARAMETER_ASSERTION_REFERENCE) String artifact,
                                     @QueryParam(PROVIDER_PARAMETER_STATE) String state,
                                     @QueryParam(PROVIDER_PARAMETER_ERROR) String error) {
            return processAuthReponse(state, artifact, error);
        }
        
        @POST
        public Response authResponsePOST(@Context HttpServletRequest request,
                                         @Context UriInfo uriInfo,
                                         MultivaluedMap<String, String> params) {
            String state = params.getFirst("state");
            String artifact = params.getFirst("artifact");
            String error = params.getFirst("error");
            return processAuthReponse(state, artifact, error);
        }
        
        private Response processAuthReponse(String state, String artifact, String error) {
            if (error != null) {
                if (error.equals(ACCESS_DENIED)) {
                    logger.error(ACCESS_DENIED + " for authentication by External IdP " + getConfig().getProviderId());
                    return callback.cancelled(state);
                } else {
                    logger.error(error + " for authentication by External IdP " + getConfig().getProviderId());
                    return callback.error(state, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }
            }
            try {
                // TODO : have to verify state and artifact values
                if (state != null && artifact != null) {
                    BrokeredIdentityContext federatedIdentity = getFederatedIdentity(artifact);
                    federatedIdentity.setCode(state);
                    return callback.authenticated(federatedIdentity);
                }
            } catch (Exception e) {
                logger.error("Failed to call delegating authentication identity provider's callback method.", e);
            }
            event.event(EventType.LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }
    }
}

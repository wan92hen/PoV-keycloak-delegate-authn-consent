package org.keycloak.examples.broker.delegate;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ConfigConstants;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import com.fasterxml.jackson.databind.JsonNode;

public class DelegateAuthnConsentClaimToRoleMapper  extends AbstractIdentityProviderMapper {
    public static final String CLAIM = "claim";
    public static final String CLAIM_VALUE = "claim.value";
    
    public static final String[] COMPATIBLE_PROVIDERS = {DelegateAuthnConsentIdentityProviderFactory.PROVIDER_ID};

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        ProviderConfigProperty property1;
        property1 = new ProviderConfigProperty();
        property1.setName(CLAIM);
        property1.setLabel("Claim");
        property1.setHelpText("Name of claim to search for in token.  You can reference nested claims using a '.', i.e. 'address.locality'.");
        property1.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property1);
        property1 = new ProviderConfigProperty();
        property1.setName(CLAIM_VALUE);
        property1.setLabel("Claim Value");
        property1.setHelpText("Value the claim must have.  If the claim is an array, then the value must be contained in the array.");
        property1.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property1);
        property = new ProviderConfigProperty();
        property.setName(ConfigConstants.ROLE);
        property.setLabel("Role");
        property.setHelpText("Role to grant to user if claim is present.  Click 'Select Role' button to browse roles, or just type it in the textbox.  To reference an application role the syntax is appname.approle, i.e. myapp.myrole");
        property.setType(ProviderConfigProperty.ROLE_TYPE);
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "delegate-authn-consent-role-idp-mapper";
    
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
    
    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Role Importer";
    }

    @Override
    public String getDisplayType() {
        return "Claim to Role";
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String roleName = mapperModel.getConfig().get(ConfigConstants.ROLE);
        if (hasClaimValue(mapperModel, context)) {
            RoleModel role = KeycloakModelUtils.getRoleFromString(realm, roleName);
            if (role == null) throw new IdentityBrokerException("Unable to find role: " + roleName);
            user.grantRole(role);
        }
    }
    
    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String roleName = mapperModel.getConfig().get(ConfigConstants.ROLE);
        RoleModel role = KeycloakModelUtils.getRoleFromString(realm, roleName);
        if (role == null) throw new IdentityBrokerException("Unable to find role: " + roleName);
        if (!hasClaimValue(mapperModel, context)) {
            user.deleteRoleMapping(role);
        } else {
            user.grantRole(role);
        }
    }

    @Override
    public String getHelpText() {
        return "If a claim exists, grant the user the specified realm or application role.";
    }
    
    protected boolean hasClaimValue(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        Object value = getClaimValue(mapperModel, context);
        String desiredValue = mapperModel.getConfig().get(CLAIM_VALUE);
        return valueEquals(desiredValue, value);
    }
    
    public static Object getClaimValue(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String claim = mapperModel.getConfig().get(CLAIM);
        return getClaimValue(context, claim);
    }
    
    public static Object getClaimValue(BrokeredIdentityContext context, String claim) {
            JsonNode profileJsonNode = (JsonNode) context.getContextData().get(AbstractJsonUserAttributeMapper.CONTEXT_JSON_NODE);
            Object value = AbstractJsonUserAttributeMapper.getJsonValue(profileJsonNode, claim);
            if (value != null) return value;
            return null;
    }
    
    public boolean valueEquals(String desiredValue, Object value) {
        if (value instanceof String) {
            if (desiredValue.equals(value)) return true;
        } else if (value instanceof Double) {
            try {
                if (Double.valueOf(desiredValue).equals(value)) return true;
            } catch (Exception e) {

            }
        } else if (value instanceof Integer) {
            try {
                if (Integer.valueOf(desiredValue).equals(value)) return true;
            } catch (Exception e) {

            }
        } else if (value instanceof Boolean) {
            try {
                if (Boolean.valueOf(desiredValue).equals(value)) return true;
            } catch (Exception e) {

            }
        } else if (value instanceof List) {
            List<?> list = (List<?>)value;
            for (Object val : list) {
                if (valueEquals(desiredValue, val)) return true;
            }
        }
        return false;
    }
    
}

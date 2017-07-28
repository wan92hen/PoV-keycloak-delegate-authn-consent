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
package org.keycloak.examples.broker.delegate;

import java.util.List;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class DelegateAuthnUserAttributeMapper extends AbstractJsonUserAttributeMapper {

	private static final String[] cp = new String[] { DelegateAuthnIdentityProviderFactory.PROVIDER_ID };

	@Override
	public String[] getCompatibleProviders() {
		return cp;
	}

	@Override
	public String getId() {
		return "delegate-authn-user-attribute-mapper";
	}
	
	@Override
	public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
		String attribute = mapperModel.getConfig().get(CONF_USER_ATTRIBUTE);
        List<String> current = user.getAttribute(attribute);
        // fetch attribute values as list
		List<String> values = (List<String>) context.getContextData().get(Constants.USER_ATTRIBUTES_PREFIX + attribute);
        if (values == null && current != null) {
       		user.removeAttribute(attribute);
        } else if (current != null) {
     		user.setAttribute(attribute, values);
        }
	}
}

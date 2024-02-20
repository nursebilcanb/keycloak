package org.keycloak.turksat.esign;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.turksat.TurksatIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class EsignIdentityProviderFactory extends AbstractIdentityProviderFactory<EsignIdentityProvider> implements TurksatIdentityProviderFactory<EsignIdentityProvider> {

    public static final String PROVIDER_ID = "esign";
    @Override
    public String getName() {
        return "E Imza";
    }

    @Override
    public EsignIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new EsignIdentityProvider(session,new EsignIdentityProviderConfig(model));
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new EsignIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create().property()
                .name("backendUrl").label("Backend URL").helpText("Override the default Base URL for this identity provider.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add().build();
    }
}

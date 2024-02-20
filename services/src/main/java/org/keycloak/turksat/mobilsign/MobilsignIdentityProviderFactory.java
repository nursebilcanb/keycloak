package org.keycloak.turksat.mobilsign;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.turksat.TurksatIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class MobilsignIdentityProviderFactory extends AbstractIdentityProviderFactory<MobilsignIdentityProvider> implements TurksatIdentityProviderFactory<MobilsignIdentityProvider> {

    public static final String PROVIDER_ID = "mobilsign";

    @Override
    public String getName() {
        return "Mobil Sign";
    }


    @Override
    public MobilsignIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new MobilsignIdentityProvider(session, new MobilsignIdentityProviderConfig(model));
    }

    @Override
    public MobilsignIdentityProviderConfig createConfig(){
        return new MobilsignIdentityProviderConfig();
    }
//    @Override
//    public OAuth2IdentityProviderConfig createConfig() {
//        return new OAuth2IdentityProviderConfig();
//    }

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

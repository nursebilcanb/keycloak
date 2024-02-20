package org.keycloak.broker.turksat;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class TurksatProviderSpi implements Spi {

    public static final String TURKSAT_SPI_NAME = "turksat";

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return TURKSAT_SPI_NAME;
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return TurksatIdentityProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return TurksatIdentityProviderFactory.class;
    }
}

package org.keycloak.turksat.mobilsign;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.broker.turksat.TurksatIdentityProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorResponseException;

import java.io.IOException;

public class MobilsignIdentityProvider extends AbstractOAuth2IdentityProvider implements TurksatIdentityProvider
//        extends AbstractOAuth2IdentityProvider implements TurksatIdentityProvider
{

//    public static final String BACKEND_URL = "backendUrl";
//    public static final String AUTH_FRAGMENT = "/login-actions";

    public static final String AUTH_URL = "https://bitbucket.org/site/oauth2/authorize";
    public static final String TOKEN_URL = "https://bitbucket.org/site/oauth2/access_token";
    public static final String USER_URL = "https://api.bitbucket.org/2.0/user";
    public static final String USER_EMAIL_URL = "https://api.bitbucket.org/2.0/user/emails";
    public static final String EMAIL_SCOPE = "email";
    public static final String ACCOUNT_SCOPE = "account";
    public static final String DEFAULT_SCOPE = ACCOUNT_SCOPE;

    public MobilsignIdentityProvider(KeycloakSession session, MobilsignIdentityProviderConfig config) {
        super(session, config);
//        String backendUrl = getUrlFromConfig(config,BACKEND_URL,"defaultValue yok");
//        String authUrl = backendUrl + AUTH_FRAGMENT;
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        String defaultScope = config.getDefaultScope();

        if (defaultScope ==  null || defaultScope.trim().equals("")) {
            config.setDefaultScope(ACCOUNT_SCOPE + " " + EMAIL_SCOPE);
        }
    }

    protected static String getUrlFromConfig(MobilsignIdentityProviderConfig config, String key, String defaultValue) {
        String url = config.getConfig().get(key);
        if (url == null || url.trim().isEmpty()) {
            url = defaultValue;
        }
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        return url;
    }
//    @Override
//    protected SimpleHttp buildUserInfoRequest(String subjectToken, String userInfoUrl){
//        String URL = USER_URL + "&access_token="+ subjectToken + "&backendUrl" + getConfig().getBackendUrl();
//        return SimpleHttp.doGet(URL,session);
//    }

//    private boolean getResponseFromFingerPrint(String subject, String operator, String gsmNo, String tcNo) {
//        String url = "https://www.belgenet.com.tr/mobil-imza-service/mobilImzaLogin";
//
//        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
//            HttpPost httpPost = new HttpPost(url);
//            httpPost.setHeader("Content-Type", "application/json");
//
//            String requestData = String.format("{\"subject\":\"%s\",\"operator\":\"%s\",\"gsmNo\":\"%s\",\"tcNo\":\"%s\"}",
//                    subject, operator, gsmNo, tcNo);
//
//            StringEntity requestEntity = new StringEntity(requestData);
//            httpPost.setEntity(requestEntity);
//
//            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
//                HttpEntity entity = response.getEntity();
//                if (entity != null) {
//                    String responseBody = EntityUtils.toString(entity);
//                    if (responseBody.contains("\"basarili\": true")) {
//                        return true;
//                    } else {
//                        return false;
//                    }
//                } else {
//                    return false;
//                }
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//            return false;
//        }
//    }


    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return USER_URL;
    }

    @Override
    protected BrokeredIdentityContext validateExternalTokenThroughUserInfo(EventBuilder event, String subjectToken, String subjectTokenType) {
        event.detail("validation_method", "user info");
        SimpleHttp.Response response = null;
        int status = 0;
        try {
            String userInfoUrl = getProfileEndpointForValidation(event);
            response = buildUserInfoRequest(subjectToken, userInfoUrl).asResponse();
            status = response.getStatus();
        } catch (IOException e) {
            logger.debug("Failed to invoke user info for external exchange", e);
        }
        if (status != 200) {
            logger.debug("Failed to invoke user info status: " + status);
            event.detail(Details.REASON, "user info call failure");
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
        }
        JsonNode profile = null;
        try {
            profile = response.asJson();
        } catch (IOException e) {
            event.detail(Details.REASON, "user info call failure");
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
        }
        String type = getJsonProperty(profile, "type");
        if (type == null) {
            event.detail(Details.REASON, "no type data in user info response");
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);

        }
        if (type.equals("error")) {
            JsonNode errorNode = profile.get("error");
            if (errorNode != null) {
                String errorMsg = getJsonProperty(errorNode, "message");
                event.detail(Details.REASON, "user info call failure: " + errorMsg);
                event.error(Errors.INVALID_TOKEN);
                throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
            } else {
                event.detail(Details.REASON, "user info call failure");
                event.error(Errors.INVALID_TOKEN);
                throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);
            }
        }
        if (!type.equals("user")) {
            event.detail(Details.REASON, "no user info in response");
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);

        }
        String id = getJsonProperty(profile, "account_id");
        if (id == null) {
            event.detail(Details.REASON, "user info call failure");
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_TOKEN, "invalid token", Response.Status.BAD_REQUEST);

        }
        return extractUserInfo(subjectToken, profile);
    }

    private BrokeredIdentityContext extractUserInfo(String subjectToken, JsonNode profile) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "account_id"));


        String username = getJsonProperty(profile, "username");
        user.setUsername(username);
        user.setName(getJsonProperty(profile, "display_name"));
        user.setIdpConfig(getConfig());
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        try {
            JsonNode emails = SimpleHttp.doGet(USER_EMAIL_URL, session).header("Authorization", "Bearer " + subjectToken).asJson();

            // {"pagelen":10,"values":[{"is_primary":true,"is_confirmed":true,"type":"email","email":"bburke@redhat.com","links":{"self":{"href":"https://api.bitbucket.org/2.0/user/emails/bburke@redhat.com"}}}],"page":1,"size":1}
            JsonNode emailJson = emails.get("values");
            if (emailJson != null) {
                if (emailJson.isArray()) {
                    emailJson = emailJson.get(0);
                }
                if (emailJson != null && "email".equals(getJsonProperty(emailJson, "type"))) {
                    user.setEmail(getJsonProperty(emailJson, "email"));

                }
            }
        } catch (Exception ignore) {
            logger.debug("failed to get email from BitBucket", ignore);

        }
        return user;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try {
            JsonNode profile = SimpleHttp.doGet(USER_URL, session).header("Authorization", "Bearer " + accessToken).asJson();

            String type = getJsonProperty(profile, "type");
            if (type == null) {
                throw new IdentityBrokerException("Could not obtain account information from bitbucket.");

            }
            if (type.equals("error")) {
                JsonNode errorNode = profile.get("error");
                if (errorNode != null) {
                    String errorMsg = getJsonProperty(errorNode, "message");
                    throw new IdentityBrokerException("Could not obtain account information from bitbucket.  Error: " + errorMsg);
                } else {
                    throw new IdentityBrokerException("Could not obtain account information from bitbucket.");
                }
            }
            if (!type.equals("user")) {
                logger.debug("Unknown object type: " + type);
                throw new IdentityBrokerException("Could not obtain account information from bitbucket.");

            }
            return extractUserInfo(accessToken, profile);
        } catch (Exception e) {
            if (e instanceof IdentityBrokerException) throw (IdentityBrokerException)e;
            throw new IdentityBrokerException("Could not obtain user profile from bitbucket.", e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }
}

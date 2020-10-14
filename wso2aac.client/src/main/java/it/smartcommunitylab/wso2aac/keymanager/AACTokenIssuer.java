package it.smartcommunitylab.wso2aac.keymanager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.KeyManager;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;

public class AACTokenIssuer extends OauthTokenIssuerImpl {

    private static final Log log = LogFactory.getLog(AACTokenIssuer.class);

    public String accessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        log.debug("issue access token for oauthAuthz");
        log.trace("oauthAuthzMsgCtx for consumerKey " + oauthAuthzMsgCtx.getAuthorizationReqDTO().getConsumerKey());
        String token = super.accessToken(oauthAuthzMsgCtx);
        log.trace("got token from internal " + token);
        return token;
    }

    @Override
    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        log.debug("issue access token for oauthToken");
        log.trace("tokReqMsgCtx for clientId" + tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());

        OAuth2AccessTokenReqDTO tokenRequest = tokReqMsgCtx.getOauth2AccessTokenReqDTO();

        String token = super.accessToken(tokReqMsgCtx);
        log.trace("got token from internal " + token);

        // bind to keymanager
        KeyManager keyManager = KeyManagerHolder.getKeyManagerInstance();

        // build request
        // we really don't care about details such as grant type scopes etc
        // keymanager idp will handle it
        // TODO move to a proper service and share between components
        AccessTokenRequest request = new AccessTokenRequest();
        // manually map
        request.setClientId(tokenRequest.getClientId());
        request.setClientSecret(tokenRequest.getClientSecret());
        request.setGrantType(tokenRequest.getGrantType());
        request.setScope(tokenRequest.getScope());
        request.setCallbackURI(tokenRequest.getCallbackURI());
        request.setResourceOwnerUsername(tokenRequest.getResourceOwnerUsername());
        request.setResourceOwnerPassword(tokenRequest.getResourceOwnerPassword());

        try {
            AccessTokenInfo info = keyManager.getNewApplicationAccessToken(request);
            token = info.getAccessToken();
            log.trace("got token from keymanager " + token);

        } catch (APIManagementException e) {
            log.error("error generating via keymanager", e);
            throw new OAuthSystemException(e);
        }

        // NOTE: apim handles everything internally, we pass only the accessToken string
        // this means that if scopes/expire/audience etc do not match apim will break...
        // TODO just delegate everything to the idp, requires a deeper integration..
        return token;
    }
};
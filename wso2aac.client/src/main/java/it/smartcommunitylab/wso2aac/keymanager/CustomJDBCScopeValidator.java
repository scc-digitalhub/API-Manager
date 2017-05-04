package it.smartcommunitylab.wso2aac.keymanager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ResourceScopeCacheEntry;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;


/**
 * The JDBC Scope Validation implementation. This validates the Resource's scope (stored in IDN_OAUTH2_RESOURCE_SCOPE)
 * against the Access Token's scopes.
 */
public class CustomJDBCScopeValidator extends OAuth2ScopeValidator {

    Log log = LogFactory.getLog(CustomJDBCScopeValidator.class);

    @Override
    public boolean validateScope(AccessTokenDO accessTokenDO, String resource) throws IdentityOAuth2Exception {

        //Get the list of scopes associated with the access token
        String[] scopes = accessTokenDO.getScope();

        //If no scopes are associated with the token
        if (scopes == null || scopes.length == 0) {
            return true;
        }

        String resourceScope = null;
        TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();

        boolean cacheHit = false;
        // Check the cache, if caching is enabled.
        if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
            OAuthCache oauthCache = OAuthCache.getInstance();
            OAuthCacheKey cacheKey = new OAuthCacheKey(resource);
            CacheEntry result = oauthCache.getValueFromCache(cacheKey);

            //Cache hit
            if (result instanceof ResourceScopeCacheEntry) {
                resourceScope = ((ResourceScopeCacheEntry) result).getScope();
                cacheHit = true;
            }
        }

        if (!cacheHit) {
            resourceScope = tokenMgtDAO.findScopeOfResource(resource);

            if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
                OAuthCache oauthCache = OAuthCache.getInstance();
                OAuthCacheKey cacheKey = new OAuthCacheKey(resource);
                ResourceScopeCacheEntry cacheEntry = new ResourceScopeCacheEntry(resourceScope);
                //Store resourceScope in cache even if it is null (to avoid database calls when accessing resources for
                //which scopes haven't been defined).
                oauthCache.addToCache(cacheKey, cacheEntry);
            }
        }

        //Return TRUE if - There does not exist a scope definition for the resource
        if (resourceScope == null) {
            if(log.isDebugEnabled()){
                log.debug("Resource '" + resource + "' is not protected with a scope");
            }
            return true;
        }

        List<String> scopeList = new ArrayList<>(Arrays.asList(scopes));

        //If the access token does not bear the scope required for accessing the Resource.
        if(!scopeList.contains(resourceScope)){
            if(log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)){
                log.debug("Access token '" + accessTokenDO.getAccessToken() + "' does not bear the scope '" +
                            resourceScope + "'");
            }
            return false;
        }
        
        return true;
    }
}

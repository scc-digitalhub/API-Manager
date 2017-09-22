/*******************************************************************************
 * Copyright 2015 Fondazione Bruno Kessler
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 ******************************************************************************/

package it.smartcommunitylab.wso2aac.grants;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;

/**
 * @author raman
 *
 */
public class NativeGrantType extends AbstractAuthorizationGrantHandler  {

	    private static Log log = LogFactory.getLog(NativeGrantType.class);

	    @Override
	    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)  throws IdentityOAuth2Exception {

	        log.info("Native handler is hit");
	        throw new IdentityOAuth2Exception("WSO2 token endpoints should not be called directly");

	        // TODO consider redirect to AAC
//            AuthenticatedUser mobileUser = new AuthenticatedUser();
//            mobileUser.setUserName(mobileNumber);
//            oAuthTokenReqMessageContext.setAuthorizedUser(mobileUser);
//            oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());
//	        return true;
	    }


	    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
	            throws IdentityOAuth2Exception 
	    {
	        return true;
	    }


	    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception 
	    {
	        return true;
	    }
}

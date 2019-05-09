# API-Manager Modified Themes
	- Store. 
	- Publisher.

# Setup Store Theme

## Create Files/Folder
- create a folder "scLab/css" inside of "jaggeryapps/store/site/themes/wso2/subthemes" folder.
- create a file call "custom.css" inside of this css folder.

## Upload Images
- jaggeryapps/store/site/themes/wso2/images/logoCompleto.png
- jaggeryapps/store/site/themes/wso2/libs/theme-wso2_1.0/images/logoCompleto.png

## Update Files
### update this list of files:
- jaggeryapps/store/site/conf/site.json
- jaggeryapps/store/site/themes/wso2/libs/theme-wso2_1.0/css/theme-wso2.css
- jaggeryapps/store/site/themes/wso2/subthemes/scLab/css/custom.css
- jaggeryapps/store/site/themes/wso2/templates/api/tenant-stores-listing/template.jag
- jaggeryapps/store/site/themes/wso2/templates/layout/base/template.jag
- jaggeryapps/store/site/themes/wso2/templates/menu/header/template.jag
- jaggeryapps/store/site/themes/wso2/templates/menu/primary/template.jag
- jaggeryapps/store/site/themes/wso2/templates/page/base/template.jag
- jaggeryapps/store/site/themes/wso2/templates/search/api-search/template.jag
- jaggeryapps/store/site/themes/wso2/templates/user/login/template.jag


# Setup Publisher Theme

## Create Files/Folder
- create a folder "scLab/css" inside of "jaggeryapps/publisher/site/themes/wso2/subthemes" folder.
- create a file call "custom.css" inside of this css folder.

## Upload Images
- jaggeryapps/publisher/site/themes/wso2/images/logoCompleto.png
- jaggeryapps/publisher/site/themes/wso2/libs/theme-wso2_1.0/images/logoCompleto.png

## Update Files
### update this list of files:
- jaggeryapps/publisher/site/conf/site.json
- jaggeryapps/publisher/site/themes/wso2/libs/theme-wso2_1.0/css/theme-wso2.css
- jaggeryapps/publisher/site/themes/wso2/subthemes/scLab/css/custom.css
- jaggeryapps/publisher/site/themes/wso2/templates/footer/template.jag
- jaggeryapps/publisher/site/themes/wso2/templates/listing/template.jag
- jaggeryapps/publisher/site/themes/wso2/templates/menu/actions/template.jag
- jaggeryapps/publisher/site/themes/wso2/templates/menu/left/template.jag
- jaggeryapps/publisher/site/themes/wso2/templates/page/base/template.jag
- jaggeryapps/publisher/site/themes/wso2/templates/search/api-search/template.jag
- jaggeryapps/publisher/site/themes/wso2/templates/user/login/template.jag

# Single Sign On in Publisher/Store

API Manager already has integrated OpenID Connect for managing single sign-on in Publisher and Store.<br/>
In order to make it compatible with AAC OAuth2 Provider it is necessary to provide methods for accessing Roles resources.<br/>
This extension is made possible through the following list of file changes:<br/>

## Files/Folders changes for Publisher
- jaggeryapps/publisher/jagg/jaggery_oidc_acs.jag
- jaggeryapps/publisher/jagg/jaggery_roles.jag
- jaggeryapps/publisher/site/blocks/use/select_tenant
- jaggeryapps/publisher/site/conf/locales/jaggery/locale_default.json
- jaggeryapps/publisher/site/conf/site.json
- jaggeryapps/publisher/site/pages/select_tenant.jag
- jaggeryapps/publisher/site/themes/wso2/templates/user/select_tenant

Regarding the configuration inside site.json below you can find one example of configuration: <br/>
> 
    "oidcConfiguration" : {
      "enabled" : "true",
      "issuer" : "API_PUBLISHER",
      "identityProviderURI" : "http://localhost:8080/aac",
      "authorizationEndpointURI" : "http://localhost:8080/aac/oauth/authorize",
      "tokenEndpointURI" : "http://localhost:8080/aac/oauth/token",
      "userInfoURI" : "http://localhost:8080/aac/userinfo",
      "jwksURI" : "http://localhost:8080/aac/jwk",
      "logoutEndpointURI" : "http://localhost:8080/aac/endsession",
      "authHttpMethod": "POST",
      "rolesEndpointURI" : "http://localhost:8080/aac/userroles/me",
      "clientConfiguration" : {
        "clientId" : "API_MGT_CLIENT_ID",
        "clientSecret" : "e17d7e15-3e04-403c-87e0-a28b630b3fb5",
        "responseType" : "code",
        "authorizationType" : "authorization_code",
        "scope" : "openid email profile user.roles.me user.roles.read",
        "redirectURI" : "$APIM_URL/publisher/jagg/jaggery_oidc_acs.jag",
        "postLogoutRedirectURI" : "https://localhost:9443/publisher/",
	"clientAlgorithm" : "RS256",
	"context":"apimanager"
      }
     }

## Files/Folders changes for Store
- jaggeryapps/publisher/jagg/jaggery_oidc_acs.jag
- jaggeryapps/publisher/jagg/jaggery_roles.jag
- jaggeryapps/publisher/site/conf/site.json

The configuration inside site.json is similar to the configuration of publisher<br>
Regarding the configuration on AAC side it is important to add to the redirect URL the following values:<br> $APIM_URL/publisher/jagg/jaggery_oidc_acs.jag  
$APIM_URL/store/jagg/jaggery_oidc_acs.jag  


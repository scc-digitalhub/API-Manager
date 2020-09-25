package it.smartcommunitylab.wso2aac.keymanager.model;

import java.util.Collection;
import java.util.Map;

public class APIMClient {
    public static final String SEPARATOR = ",";

    private String clientId;
    private String clientSecret;
    private String clientSecretMobile;
    private String name;
    private String displayName;
    private String redirectUris;
    private Collection<String> grantedTypes;

    private boolean nativeAppsAccess;
    private Map<String, Map<String, Object>> providerConfigurations;
    private String mobileAppSchema;

    private Map<String, Boolean> identityProviders;
    private Map<String, Boolean> identityProviderApproval;

    private String userName;
    private String scope;

    private Map<String, String> parameters;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getClientSecretMobile() {
        return clientSecretMobile;
    }

    public void setClientSecretMobile(String clientSecretMobile) {
        this.clientSecretMobile = clientSecretMobile;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(String redirectUris) {
        this.redirectUris = redirectUris;
    }

    public Collection<String> getGrantedTypes() {
        return grantedTypes;
    }

    public void setGrantedTypes(Collection<String> grantedTypes) {
        this.grantedTypes = grantedTypes;
    }

    public boolean isNativeAppsAccess() {
        return nativeAppsAccess;
    }

    public void setNativeAppsAccess(boolean nativeAppsAccess) {
        this.nativeAppsAccess = nativeAppsAccess;
    }

    public Map<String, Map<String, Object>> getProviderConfigurations() {
        return providerConfigurations;
    }

    public void setProviderConfigurations(Map<String, Map<String, Object>> providerConfigurations) {
        this.providerConfigurations = providerConfigurations;
    }

    public String getMobileAppSchema() {
        return mobileAppSchema;
    }

    public void setMobileAppSchema(String mobileAppSchema) {
        this.mobileAppSchema = mobileAppSchema;
    }

    public Map<String, Boolean> getIdentityProviders() {
        return identityProviders;
    }

    public void setIdentityProviders(Map<String, Boolean> identityProviders) {
        this.identityProviders = identityProviders;
    }

    public Map<String, Boolean> getIdentityProviderApproval() {
        return identityProviderApproval;
    }

    public void setIdentityProviderApproval(Map<String, Boolean> identityProviderApproval) {
        this.identityProviderApproval = identityProviderApproval;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    public String getParameter(String key) {
        if (this.parameters.containsKey(key)) {
            return this.parameters.get(key);

        }

        return null;
    }

    @Override
    public String toString() {
        return "APIMClient [clientId=" + clientId + ", clientSecret=" + clientSecret + ", name=" + name
                + ", displayName=" + displayName + ", redirectUris=" + redirectUris + ", grantedTypes=" + grantedTypes
                + ", identityProviderApproval=" + identityProviderApproval + ", userName=" + userName + ", scope="
                + scope + ", parameters=" + parameters + "]";
    }

    
}

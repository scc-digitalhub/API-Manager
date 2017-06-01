package it.smartcommunitylab.aac.wso2.model;

import java.util.List;

public class CorsConfiguration {

	private List<String> accessControlAllowOrigins;
	private List<String> accessControlAllowHeaders;
	private List<String> accessControlAllowMethods;
	
	private boolean accessControlAllowCredentials;
	private boolean corsConfigurationEnabled;

	public boolean getAccessControlAllowCredentials() {
		return this.accessControlAllowCredentials;
	}

	public List<String> getAccessControlAllowHeaders() {
		return this.accessControlAllowHeaders;
	}

	public List<String> getAccessControlAllowMethods() {
		return this.accessControlAllowMethods;
	}

	public List<String> getAccessControlAllowOrigins() {
		return this.accessControlAllowOrigins;
	}

	public boolean getCorsConfigurationEnabled() {
		return this.corsConfigurationEnabled;
	}

	public void setAccessControlAllowCredentials(boolean accessControlAllowCredentials) {
		this.accessControlAllowCredentials = accessControlAllowCredentials;
	}

	public void setAccessControlAllowHeaders(List<String> accessControlAllowHeaders) {
		this.accessControlAllowHeaders = accessControlAllowHeaders;
	}

	public void setAccessControlAllowMethods(List<String> accessControlAllowMethods) {
		this.accessControlAllowMethods = accessControlAllowMethods;
	}

	public void setAccessControlAllowOrigins(List<String> accessControlAllowOrigins) {
		this.accessControlAllowOrigins = accessControlAllowOrigins;
	}

	public void setCorsConfigurationEnabled(boolean corsConfigurationEnabled) {
		this.corsConfigurationEnabled = corsConfigurationEnabled;
	}

}

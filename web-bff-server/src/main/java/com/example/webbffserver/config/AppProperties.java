package com.example.webbffserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private String baseUrl;
    private Ports ports;

    @Data
    public static class Ports {
        private int authServer;
        private int frontend;
        private int authGateway;
    }

    public String getAuthServerUrl() {
        return baseUrl + ":" + ports.getAuthServer();
    }

    public String getAuthGatewayUrl() {
        return baseUrl + ":" + ports.getAuthGateway();
    }

    public String getFrontendUrl() {
        return baseUrl + ":" + ports.getFrontend();
    }

    public String getAuthServerTokenUrl(){
        return  getAuthServerUrl() + "/oauth2/token";
    }

    public String getAuthGatewayCallbackUrl() {
        return  getAuthGatewayUrl() + "/api/auth/callback";
    }

    public String getAuthServerAuthorizeUrl() {
        return  getAuthServerUrl() + "/oauth2/authorize";
    }

    public String getAuthServerLogoutUrl() {
        return  getAuthServerUrl() + "/logout";
    }

    public String getAuthServerJwkSetUrl() { return getAuthServerUrl() + "/.well-known/jwks.json"; }

    public String getAuthServerUserInfoUrl() { return getAuthServerUrl() + "/userinfo"; }

}

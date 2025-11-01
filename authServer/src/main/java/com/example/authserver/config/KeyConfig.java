package com.example.authserver.config;

import com.example.authserver.config.properties.AppProperties;
import com.example.util.Jwk;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

@Configuration
public class KeyConfig {

    /**
     * Authorization Server가 JWT 토큰을 서명할 때 사용하는 RSA 키
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwk.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (selector, context) -> selector.select(jwkSet);
    }

    /**
     * Resource Server에서 JWT 토큰을 검증할 때 사용하는 디코더
     * @param jwkSource
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * OAuth2 표준: Authorization Server의 고정 URL 설정
     * @param props
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(AppProperties props) {
        return AuthorizationServerSettings.builder()
                .issuer(props.getAuthServerUrl())
                .build();
    }
}

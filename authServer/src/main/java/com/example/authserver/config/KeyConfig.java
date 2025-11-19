package com.example.authserver.config;

import com.example.authserver.config.properties.AppProperties;
import com.example.authserver.entity.CustomUserDetails;
import com.example.util.Jwk;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Slf4j
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
     *
     * @param jwkSource
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * OAuth2 표준: Authorization Server의 고정 URL 설정
     *
     * @param props
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(AppProperties props) {
        return AuthorizationServerSettings.builder()
                .issuer(props.getAuthServerUrl())
                .build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            // 디버그: 어떤 토큰 타입이 들어오는지 확인
            String tokenTypeValue = context.getTokenType().getValue();
            log.debug("🔍 Token Type: {}", tokenTypeValue);
            log.debug("🔍 OidcParameterNames.ID_TOKEN: {}", OidcParameterNames.ID_TOKEN);
            log.debug("🔍 비교 결과: {}", tokenTypeValue.equals(OidcParameterNames.ID_TOKEN));

            // ID Token에만 claims 추가
            if (tokenTypeValue.equals(OidcParameterNames.ID_TOKEN)) {
                log.debug("✅ ID Token 처리 시작");
                Authentication principal = context.getPrincipal();
                CustomUserDetails user = (CustomUserDetails) principal.getPrincipal();

                context.getClaims().claim("id", user.getId().toString());
                context.getClaims().claim("loginId", user.getLoginId());
                context.getClaims().claim("name", user.getUsername());
                context.getClaims().claim("email", user.getEmail() == null ? "" : user.getEmail());
                context.getClaims().claim("phone", user.getPhone() == null ? "" : user.getPhone());
                context.getClaims().claim("role", user.getRole());
                log.debug("✅ ID Token claims 추가 완료");
            } else {
                log.debug("⏭️ ID Token이 아니므로 claims 추가하지 않음: {}", tokenTypeValue);
            }
        };
    }

}

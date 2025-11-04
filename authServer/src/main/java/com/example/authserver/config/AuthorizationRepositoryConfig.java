package com.example.authserver.config;

import com.example.authserver.config.properties.AppProperties;
import com.example.authserver.service.RedisOAuth2AuthorizationConsentService;
import com.example.authserver.service.RedisOAuth2AuthorizationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class AuthorizationRepositoryConfig {

    private final AppProperties appProperties;

    /**
     * OAuth2 Client 등록
     * @param passwordEncoder
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        List<RegisteredClient> clients = new ArrayList<>();

        // === BFF Client (auth-gateway) ===
        RegisteredClient bffClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("bff-client")
                .clientSecret(passwordEncoder.encode("bff-secret"))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(appProperties.getAuthGatewayCallbackUrl()) // BFF가 code 받는 URI
                .scope("openid")
                .scope("profile")
                .scope("email")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(false) // 서버 간 통신이라 PKCE 불필요
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        clients.add(bffClient);

        System.out.println("Registered clientSecret: " + bffClient.getClientSecret());

        return new InMemoryRegisteredClientRepository(clients);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            RedisTemplate<String, Object> redisTemplate,
            RegisteredClientRepository registeredClientRepository,
            ObjectMapper objectMapper) {
        return new RedisOAuth2AuthorizationService(redisTemplate, registeredClientRepository,objectMapper);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            RedisTemplate<String, Object> redisTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new RedisOAuth2AuthorizationConsentService(redisTemplate, registeredClientRepository);
    }


}

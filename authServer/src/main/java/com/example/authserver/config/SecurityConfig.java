package com.example.authserver.config;

import com.example.authserver.service.CustomOidcUserService;
import com.example.authserver.service.CustomOAuth2UserService;
import com.example.authserver.service.RedisOAuth2AuthorizationConsentService;
import com.example.authserver.service.RedisOAuth2AuthorizationService;
import com.example.util.Jwk;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import com.example.authserver.handler.OAuth2LoginSuccessHandler;
import com.example.authserver.handler.FormLoginSuccessHandler;

import java.time.Duration;
import java.util.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableConfigurationProperties(AppProperties.class)
public class SecurityConfig {

    private final OAuth2LoginSuccessHandler oauth2LoginSuccessHandler;
    private final FormLoginSuccessHandler formLoginSuccessHandler;
    private final AppProperties appProperties;
    private final RedisTemplate<String, Object> redisTemplate;
    private final RegisteredClientRepository registeredClientRepository;

    // ========================================
    // OAuth2 Authorization Server 필터 체인
    // ========================================
    // 이 필터 체인이 실제 OAuth2 Authorization Server의 역할을 담당
    // Spring이 자동으로 다음 엔드포인트들을 제공:
    // - GET /oauth2/authorize (인증 요청)
    // - POST /oauth2/token (토큰 발급) ← 여기서 Spring이 자동으로 JWT 토큰 발급!
    // - POST /oauth2/revoke (토큰 폐기)
    // - GET /.well-known/jwks.json (공개키 조회)
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // scope로 openid를 받기 위해선 oidc 설정을 따로 해줘야함
        // oidc란 기본 oauth2는 접근 권한을 주지만 사용자 인증은 하지않는대
        // oidc는 ID Token으로 사용자 정보를 가져와서 인증 가능
        //OAuth2: “이 사용자가 API 자원에 접근할 수 있는 권한이 있는가?” → 인가(Authorization) 중심
        //OIDC: “이 사용자가 누구인가?” → 인증(Authentication) 중심
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.ignoringRequestMatchers(
                        "/oauth2/token",
                        "/oauth2/introspect",
                        "/oauth2/revoke")
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(formLoginSuccessHandler)
                );

        return http.build();
    }

    // ========================================
    // OAuth2 Authorization Server 필터 체인
    // ========================================
    // BFF가 Authorization Code를 받을 수 있도록 설정
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error","/login", "/login/**", "/css/**", "/js/**", "/images/**",
                                "/.well-known/**", "/h2-console/**", 
                                "/oauth2/token", "/oauth2/jwks", "/userinfo").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(formLoginSuccessHandler)
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        // Spring이 제공하는 endpoint: /oauth2/authorization/{registrationId}
                        .loginPage("/login")
                        .successHandler(oauth2LoginSuccessHandler) // Google 로그인 성공 시 원래 authorization request 복귀
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(customOidcUserService()) // Google용 OIDC 사용자 서비스
                                .userService(customOAuth2UserService()) // 카카오용 OAuth2 사용자 서비스
                        )
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                );

        return http.build();
    }



    // ========================================
    // CORS 설정
    // ========================================
    // BFF 서버와 프론트엔드와의 통신을 위한 CORS 설정
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList(
                appProperties.getFrontendUrl(),  // SPA
                appProperties.getAuthGatewayUrl()  // BFF 서버
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // OAuth2 Client 등록
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
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.builder()
                .username("testuser")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public CustomOidcUserService customOidcUserService() {
        return new CustomOidcUserService();
    }

    @Bean
    public CustomOAuth2UserService customOAuth2UserService() {
        return new CustomOAuth2UserService();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new RedisOAuth2AuthorizationService(redisTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new RedisOAuth2AuthorizationConsentService(redisTemplate, registeredClientRepository);
    }





    // ========================================
    // JWT 서명용 키 관리
    // ========================================
    // Authorization Server가 JWT 토큰을 서명할 때 사용하는 RSA 키
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwk.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    // ========================================
    // JWT 디코더
    // ========================================
    // Resource Server에서 JWT 토큰을 검증할 때 사용하는 디코더
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // ========================================
    // Authorization Server 기본 세팅
    // ========================================
    // OAuth2 표준: Authorization Server의 고정 URL 설정
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(appProperties.getAuthServerUrl()) // OAuth2 표준: 고정 URL
                .build();
    }

}
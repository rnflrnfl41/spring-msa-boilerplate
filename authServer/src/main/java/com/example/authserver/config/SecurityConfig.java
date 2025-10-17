package com.example.authserver.config;

import com.example.authserver.service.CustomOidcUserService;
import com.example.util.Jwk;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
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
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import com.example.authserver.handler.OAuth2LoginSuccessHandler;

import java.time.Duration;
import java.util.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuth2LoginSuccessHandler oauth2LoginSuccessHandler;

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
                .formLogin(form -> form.loginPage("/login"));

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
                        .requestMatchers("/login", "/login/**", "/css/**", "/js/**", "/images/**",
                                "/.well-known/**", "/h2-console/**", 
                                "/oauth2/token", "/oauth2/jwks", "/userinfo").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        // Spring이 제공하는 endpoint: /oauth2/authorization/{registrationId}
                        .loginPage("/login")
                        .successHandler(oauth2LoginSuccessHandler) // Google 로그인 성공 시 원래 authorization request 복귀
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(customOidcUserService()) // 커스텀 OIDC 사용자 서비스
                        )
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
                "http://localhost:3000",  // SPA
                "http://localhost:9091"  // BFF 서버
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
    public RegisteredClientRepository registeredClientRepository() {
        List<RegisteredClient> clients = new ArrayList<>();

        // === BFF Client (auth-gateway) ===
        RegisteredClient bffClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("bff-client")
                .clientSecret("{noop}bff-secret") // 평문으로 저장 (개발 환경용)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:9091/api/auth/callback") // BFF가 code 받는 URI
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

        // 여기 나중에 Google, Kakao 같은 소셜 로그인 client도 추가 가능
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
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CustomOidcUserService customOidcUserService() {
        return new CustomOidcUserService();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            RegisteredClientRepository registeredClientRepository,
            JdbcTemplate jdbcTemplate) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
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
                .issuer("http://localhost:9090") // OAuth2 표준: 고정 URL
                .build();
    }

}
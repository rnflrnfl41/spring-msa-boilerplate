package com.example.authserver.config;

import com.example.util.Jwk;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
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
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

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
                // OAuth2: “이 사용자가 API 자원에 접근할 수 있는 권한이 있는가?” → 인가(Authorization) 중심
                // OIDC: “이 사용자가 누구인가?” → 인증(Authentication) 중심
                http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                                .oidc(Customizer.withDefaults());

                return http
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                                .csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/token", "/api/auth/**"))
                                .exceptionHandling(ex -> ex
                                                .authenticationEntryPoint((request, response, authException) -> {
                                                        response.setStatus(HttpStatus.UNAUTHORIZED.value());
                                                        response.setContentType("application/json");
                                                        response.getWriter().write(
                                                                        "{\"error\":\"unauthorized\",\"message\":\"Authentication required\"}");
                                                }))
                                .formLogin(AbstractHttpConfigurer::disable)
                                .build();
        }

        // ========================================
        // OAuth2 Client + Resource Server 필터 체인
        // ========================================
        // 이 필터 체인은 구글 OAuth2 Client 역할과 JWT 토큰 검증을 담당
        // OAuth2 표준에 따라 구글 로그인 성공 시 Authorization Code를 생성하여 프론트엔드로 전달
        @Bean
        @Order(2)
        public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
                return http
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                                .csrf(csrf -> csrf.disable())
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/api/auth/**", "/oauth2/**", "/.well-known/**",
                                                                "/h2-console/**")
                                                .permitAll()
                                                .anyRequest().authenticated())
                                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())).build();
        }

        // OAuth2 Client 설정 추가 (구글/카카오 연동용)
        @Bean
        public OAuth2AuthorizedClientManager authorizedClientManager(
                        ClientRegistrationRepository clientRegistrationRepository,
                        OAuth2AuthorizedClientRepository authorizedClientRepository) {

                OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder
                                .builder()
                                .authorizationCode()
                                .refreshToken()
                                .build();

                DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
                                clientRegistrationRepository, authorizedClientRepository);
                authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

                return authorizedClientManager;
        }

        // ========================================
        // CORS 설정
        // ========================================
        // 프론트엔드와의 통신을 위한 CORS 설정
        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOriginPatterns(
                                Arrays.asList("http://localhost:3000", "http://localhost:8080",
                                                "http://localhost:63342"));
                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                configuration.setAllowedHeaders(Arrays.asList("*"));
                configuration.setAllowCredentials(true);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }

        // ========================================
        // OAuth2 Client 등록 (OAuth2 표준 준수)
        // ========================================
        // OAuth2 표준에 따라 여러 클라이언트를 등록하여 SSO 지원
        @Bean
        public RegisteredClientRepository registeredClientRepository() {
                List<RegisteredClient> clients = new ArrayList<>();

                // 1. 프론트엔드 클라이언트 (React/Vue)
                RegisteredClient frontendClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("frontend-client") // clientId는 요청하는 클라이언트의 아이디와 같아야 통과
                                // clientAuthenticationMethod는 클라이언트가 Authorization Server에 자신을 인증하는 방식을 정의하는 설정
                                // (CLIENT_SECRET_BASIC는 클라이언트에서 토큰 요청 시 Authorization: Basic 헤더를 사용)
                                // react같은 open client는 client_secret를 코드에 포함시키면 누구나 개발자 도구에서 볼 수있기 때문에 None 처리
                                // 대신 PKCE를 요구하도록 설정
                                // clientSecret도 없앰
                                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                                .clientSettings(ClientSettings.builder()
                                                .requireProofKey(true)
                                                .requireAuthorizationConsent(false) // 필요시 동의 화면 끄기/켜기
                                                .build())
                                .tokenSettings(TokenSettings.builder()
                                                .accessTokenTimeToLive(Duration.ofMinutes(30))
                                                .reuseRefreshTokens(false) // refresh token rotation 권장
                                                .build())
                                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // 클라이언트가
                                                                                                   // Authorization
                                                                                                   // Server에 요청하는
                                // 권한 유형을 정의하는 설정
                                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // 다중으로 인증 방식 선택 가능
                                                                                              // (CLIENT_CREDENTIALS,
                                // AUTHORIZATION_CODE 등)
                                .redirectUri("http://localhost:3000/callback") // 클라이언트와 똑같이 설정
                                .scope("openid") // 클라이언트에서 요청 가능 한 권한 범위 (예를들어 서버의 admin 권한이 없는대 client에서 admin 권한을
                                                 // 요청하면 거절)
                                .scope("profile")
                                .scope("email")
                                .scope("read")
                                .scope("write")
                                .build();
                clients.add(frontendClient);

                // 2. 모바일 앱 클라이언트
                RegisteredClient mobileClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("mobile-client")
                                .clientSecret("{noop}mobile-secret")
                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                .redirectUri("myapp://callback")
                                .scope("read")
                                .scope("write")
                                .scope("openid")
                                .scope("profile")
                                .scope("email")
                                .build();
                clients.add(mobileClient);

                // 3. 서비스 A 클라이언트 (SSO용)
                RegisteredClient serviceAClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("service-a-client")
                                .clientSecret("{noop}service-a-secret")
                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST) // POST 방식으로
                                                                                                           // 변경
                                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                .redirectUri("http://localhost:8081/callback")
                                .scope("read")
                                .scope("write")
                                .scope("openid")
                                .scope("profile")
                                .scope("email")
                                .build();
                clients.add(serviceAClient);

                // 4. 서비스 B 클라이언트 (SSO용)
                RegisteredClient serviceBClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("service-b-client")
                                .clientSecret("{noop}service-b-secret")
                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST) // POST 방식으로
                                                                                                           // 변경
                                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                .redirectUri("http://localhost:8082/callback")
                                .scope("read")
                                .scope("write")
                                .scope("openid")
                                .scope("profile")
                                .scope("email")
                                .build();
                clients.add(serviceBClient);

                return new InMemoryRegisteredClientRepository(clients);
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

        // ========================================
        // 사용자 인증 설정 (테스트용)
        // ========================================
        // OAuth2 표준: Resource Owner Password Credentials Grant를 위한 사용자 인증
        @Bean
        public UserDetailsService userDetailsService() {
                UserDetails user = User.withDefaultPasswordEncoder()
                                .username("test@example.com")
                                .password("password")
                                .roles("USER")
                                .build();

                UserDetails admin = User.withDefaultPasswordEncoder()
                                .username("admin@example.com")
                                .password("admin")
                                .roles("ADMIN")
                                .build();

                return new InMemoryUserDetailsManager(user, admin);
        }

}

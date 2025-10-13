package com.example.authserver.config;

import com.example.util.Jwk;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
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
        //OAuth2: “이 사용자가 API 자원에 접근할 수 있는 권한이 있는가?” → 인가(Authorization) 중심
        //OIDC: “이 사용자가 누구인가?” → 인증(Authentication) 중심
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        return http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.ignoringRequestMatchers(
                        "/oauth2/token",
                        "/oauth2/introspect",
                        "/oauth2/revoke")
                )
                .exceptionHandling(
                        ex ->
                                ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .formLogin(form -> form.loginPage("/login"))
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
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/css/**", "/js/**", "/images/**").permitAll()
                        .requestMatchers("/api/auth/**", "/oauth2/**", "/.well-known/**", "/h2-console/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")                 // 커스텀 로그인 페이지 지정
                        .loginProcessingUrl("/login")        // 로그인 form action 처리
                        .defaultSuccessUrl("/", true)        // 로그인 성공 시 이동
                        .failureUrl("/login?error=true")     // 로그인 실패 시 이동
                        .permitAll()
                )
                .oauth2Login(oauth -> oauth
                        .loginPage("/login")  // 구글/카카오 로그인도 이 화면에서
                );

        return http.build();
    }

    // ========================================
    // OAuth2UserService - 구글 사용자 정보 처리
    // ========================================
    // 구글에서 받은 사용자 정보를 처리하는 서비스
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        return userRequest -> {
            DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
            OAuth2User oAuth2User = delegate.loadUser(userRequest);

            // 구글에서 받은 사용자 정보 처리
            String email = oAuth2User.getAttribute("email");
            String name = oAuth2User.getAttribute("name");
            String picture = oAuth2User.getAttribute("picture");

            // 여기서 DB에 사용자 등록/조회 로직 추가 가능
            // userService.findOrCreateUser(email, name, picture);

            return oAuth2User;
        };
    }

    // ========================================
    // CORS 설정
    // ========================================
    // 프론트엔드와의 통신을 위한 CORS 설정
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(
                Arrays.asList("http://localhost:3000", "http://localhost:8080", "http://localhost:63342"));
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
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // 클라이언트가 Authorization Server에 요청하는
                // 권한 유형을 정의하는 설정
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // 다중으로 인증 방식 선택 가능 (CLIENT_CREDENTIALS,
                // AUTHORIZATION_CODE 등)
                .redirectUri("http://localhost:3000/callback") // 클라이언트와 똑같이 설정
                .scope("openid") // 클라이언트에서 요청 가능 한 권한 범위 (예를들어 서버의 admin 권한이 없는대 client에서 admin 권한을 요청하면 거절)
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
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST) // POST 방식으로 변경
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
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST) // POST 방식으로 변경
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

        return new InMemoryUserDetailsManager(user);
    }

    // ========================================
    // Authorization Code 생성 (임시 구현)
    // ========================================
    // 실제로는 DB에 저장하고 UUID 등을 사용해야 함
    // 현재는 간단한 문자열로 구현
    private String generateAuthorizationCode(String email) {
        return "auth_code_" + email + "_" + System.currentTimeMillis();
    }

}
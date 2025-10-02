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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

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
        return http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
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
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/oauth2/**").permitAll()
                        .requestMatchers("/api/test/**").permitAll()  // 테스트 엔드포인트 허용
                        .requestMatchers("/.well-known/**").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()  // H2 콘솔 허용
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo ->
                                userInfo.userService(oAuth2UserService())
                        )
                        .successHandler((request, response, authentication) -> {
                            // ========================================
                            // OAuth2 표준: 구글 로그인 성공 시 처리
                            // ========================================
                            // OAuth2 표준에 따라 Authorization Code를 생성하여 프론트엔드로 전달
                            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
                            String email = oAuth2User.getAttribute("email");
                            String name = oAuth2User.getAttribute("name");

                            // Authorization Code 생성 (실제로는 DB에 저장해야 함)
                            String authCode = generateAuthorizationCode(email);

                            // Authorization Code 저장 (실제로는 AuthService를 주입받아서 사용해야 함)
                            // authService.saveAuthorizationCode(authCode, email);

                            // OAuth2 표준에 따라 프론트엔드로 Authorization Code 전달
                            // 프론트엔드는 이 코드를 받아서 /oauth2/token에 토큰 요청
                            response.sendRedirect("http://localhost:3000/callback?code=" + authCode);
                        })
                        .failureHandler((request, response, exception) -> {
                            response.sendRedirect("http://localhost:3000/login?error=google_login_failed");
                        })
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
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
        configuration.setAllowedOriginPatterns(Arrays.asList("http://localhost:3000", "http://localhost:8080", "http://localhost:63342"));
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
                .clientId("frontend-client")
                .clientSecret("{noop}frontend-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:3000/callback")
                .scope("read")
                .scope("write")
                .scope("openid")
                .scope("profile")
                .scope("email")
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
                .authorizationGrantType(AuthorizationGrantType.PASSWORD) // Resource Owner Password Credentials Grant
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
                .issuer("http://localhost:9090")  // OAuth2 표준: 고정 URL
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

package com.example.authserver.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * ========================================
 * OAuth2 표준 테스트 컨트롤러
 * ========================================
 * OAuth2 표준을 테스트하기 위한 컨트롤러
 * 실제 프로덕션에서는 제거해야 함
 */
@RestController
@RequestMapping("/api/test")
@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:8080"})
public class OAuth2TestController {

    /**
     * ========================================
     * 서버 상태 확인
     * ========================================
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OAuth2 Authorization Server is running!");
    }

    /**
     * ========================================
     * OAuth2 표준 테스트 가이드
     * ========================================
     * 클라이언트가 직접 OAuth2 Server에 요청하는 방법을 안내
     */
    @GetMapping("/oauth2-guide")
    public ResponseEntity<String> getOAuth2Guide() {
        String guide = """
            # OAuth2 표준 테스트 가이드
                
            ## 1. Resource Owner Password Credentials Grant
            POST /oauth2/token
            Content-Type: application/x-www-form-urlencoded
                
            grant_type=password&
            client_id=service-a-client&
            client_secret=service-a-secret&
            username=test@example.com&
            password=password&
            scope=read write
                
            ## 2. Authorization Code Grant (구글 로그인)
            ### 1단계: 인증 요청
            GET /oauth2/authorize?response_type=code&client_id=frontend-client&redirect_uri=http://localhost:3000/callback&scope=read write openid profile email
                
            ### 2단계: 토큰 요청
            POST /oauth2/token
            Content-Type: application/x-www-form-urlencoded
                
            grant_type=authorization_code&
            client_id=frontend-client&
            client_secret=frontend-secret&
            code=AUTHORIZATION_CODE&
            redirect_uri=http://localhost:3000/callback
                
            ## 3. Refresh Token Grant
            POST /oauth2/token
            Content-Type: application/x-www-form-urlencoded
                
            grant_type=refresh_token&
            client_id=frontend-client&
            client_secret=frontend-secret&
            refresh_token=REFRESH_TOKEN
                
            ## 4. Token Revocation
            POST /oauth2/revoke
            Content-Type: application/x-www-form-urlencoded
                
            token=REFRESH_TOKEN&
            client_id=frontend-client&
            client_secret=frontend-secret
                
            ## 5. 공개키 조회
            GET /.well-known/jwks.json
                
            ## 등록된 클라이언트 목록
            - frontend-client (프론트엔드)
            - mobile-client (모바일 앱)
            - service-a-client (서비스 A)
            - service-b-client (서비스 B)
            """;
        
        return ResponseEntity.ok(guide);
    }

    /**
     * ========================================
     * 등록된 클라이언트 목록 조회
     * ========================================
     * OAuth2 표준에 따라 등록된 클라이언트 목록을 조회
     */
    @GetMapping("/clients")
    public ResponseEntity<String> getRegisteredClients() {
        String clients = """
            등록된 OAuth2 클라이언트 목록:
                
            1. frontend-client
               - Secret: frontend-secret
               - Redirect URI: http://localhost:3000/callback
               - Grant Types: authorization_code, refresh_token
               - Scopes: read, write, openid, profile, email
                
            2. mobile-client
               - Secret: mobile-secret
               - Redirect URI: myapp://callback
               - Grant Types: authorization_code, refresh_token
               - Scopes: read, write, openid, profile, email
                
            3. service-a-client
               - Secret: service-a-secret
               - Redirect URI: http://localhost:8081/callback
               - Grant Types: authorization_code, refresh_token, password
               - Scopes: read, write, openid, profile, email
                
            4. service-b-client
               - Secret: service-b-secret
               - Redirect URI: http://localhost:8082/callback
               - Grant Types: authorization_code, refresh_token, password
               - Scopes: read, write, openid, profile, email
            """;
        
        return ResponseEntity.ok(clients);
    }

    /**
     * ========================================
     * OAuth2 엔드포인트 목록 조회
     * ========================================
     * Spring Authorization Server가 제공하는 OAuth2 엔드포인트 목록
     */
    @GetMapping("/endpoints")
    public ResponseEntity<String> getOAuth2Endpoints() {
        String endpoints = """
            OAuth2 표준 엔드포인트:
                
            1. Authorization Endpoint
               - URL: /oauth2/authorize
               - Method: GET
               - 용도: 인증 요청
                
            2. Token Endpoint
               - URL: /oauth2/token
               - Method: POST
               - 용도: 토큰 발급
                
            3. Token Revocation Endpoint
               - URL: /oauth2/revoke
               - Method: POST
               - 용도: 토큰 폐기
                
            4. JWK Set Endpoint
               - URL: /.well-known/jwks.json
               - Method: GET
               - 용도: 공개키 조회
                
            5. OpenID Connect Discovery
               - URL: /.well-known/openid_configuration
               - Method: GET
               - 용도: OpenID Connect 설정 조회
            """;
        
        return ResponseEntity.ok(endpoints);
    }

    /**
     * ========================================
     * 테스트용 사용자 정보
     * ========================================
     * OAuth2 표준 테스트를 위한 사용자 정보
     */
    @GetMapping("/test-user")
    public ResponseEntity<String> getTestUser() {
        String testUser = """
            테스트용 사용자 정보:
                
            이메일: test@example.com
            비밀번호: password
                
            이 정보로 Resource Owner Password Credentials Grant를 테스트할 수 있습니다.
            """;
        
        return ResponseEntity.ok(testUser);
    }
}

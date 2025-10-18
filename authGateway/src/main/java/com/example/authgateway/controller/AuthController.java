package com.example.authgateway.controller;

import com.example.authgateway.dto.TokenResponse;
import com.example.authgateway.service.TokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AuthController {

    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    private final WebClient webClient = WebClient.create();

    /**
     * Auth Server → BFF callback (Authorization Code 받음)
     * 표준 OAuth2 Authorization Code Flow
     */
    @GetMapping("/callback")
    public void callback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "error", required = false) String error,
            HttpServletResponse response
    ) {
        try {
            // 1️⃣ 에러 체크
            if (error != null) {
                log.error("❌ OAuth2 에러: {}", error);
                response.sendRedirect("http://localhost:3000?login=failed&error=" + error);
                return;
            }

            // 2️⃣ Authorization Code 체크
            if (code == null) {
                log.error("❌ Authorization Code 없음");
                response.sendRedirect("http://localhost:3000?login=failed&error=no_authorization_code");
                return;
            }

            // 3️⃣ Authorization Code로 토큰 교환 (Spring Security OAuth2 Authorization Server 사용)
            Map<String, String> tokenResponse = webClient.post()
                    .uri("http://localhost:9090/oauth2/token")
                    .headers(headers -> headers.setBasicAuth("bff-client", "bff-secret"))
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                            .with("code", code)
                            .with("redirect_uri", "http://localhost:9091/api/auth/callback")
                            .with("client_id", "bff-client"))
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {})
                    .block();

            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                log.error("❌ 토큰 교환 실패");
                response.sendRedirect("http://localhost:3000?login=failed&error=token_exchange_failed");
                return;
            }

            // 4️⃣ 토큰을 세션으로 저장
            String sessionId = UUID.randomUUID().toString();
            TokenResponse tokenObj = new TokenResponse();
            tokenObj.setAccessToken(tokenResponse.get("access_token"));
            tokenObj.setRefreshToken(tokenResponse.get("refresh_token"));
            tokenObj.setTokenType(tokenResponse.get("token_type"));
            tokenObj.setExpiresIn(Long.valueOf(tokenResponse.get("expires_in")));
            tokenObj.setScope(tokenResponse.get("scope"));

            tokenService.saveToken(sessionId, tokenObj);

            // 5️⃣ SPA에 sessionId 쿠키 전달
            Cookie sessionCookie = new Cookie("SESSION_ID", sessionId);
            sessionCookie.setHttpOnly(true);
            sessionCookie.setPath("/");
            sessionCookie.setMaxAge(7 * 24 * 60 * 60); // 7일
            response.addCookie(sessionCookie);

            // 6️⃣ SPA로 성공 리다이렉트
            response.sendRedirect("http://localhost:3000?login=success");

        } catch (Exception e) {
            log.error("❌ 로그인 콜백 처리 실패: {}", e.getMessage(), e);
            try {
                response.sendRedirect("http://localhost:3000?login=error");
            } catch (IOException ioException) {
                log.error("❌ 리다이렉트 실패: {}", ioException.getMessage());
            }
        }
    }


    /**
     * 1️⃣ SPA → BFF (로그인 요청)
     * 세션 검증 후 없으면 OAuth2 Authorization Server로 리다이렉트
     */
    @GetMapping("/login")
    public void login(HttpServletRequest request, HttpServletResponse response) {
        try {
            // 1️⃣ 세션 검증
            String sessionId = getSessionIdFromCookie(request);
            if (sessionId != null) {
                String accessToken = tokenService.getAccessToken(sessionId);
                if (accessToken != null) {
                    // 이미 로그인된 상태 - SPA로 리다이렉트
                    response.sendRedirect("http://localhost:3000?login=already");
                    return;
                }
            }

            // 2️⃣ 세션이 없으면 OAuth2 Authorization Server로 리다이렉트
            String authorizeUrl = UriComponentsBuilder.fromUriString("http://localhost:9090/oauth2/authorize")
                    .queryParam("response_type", "code")
                    .queryParam("client_id", "bff-client")
                    .queryParam("redirect_uri", "http://localhost:9091/api/auth/callback")
                    .queryParam("scope", "openid profile email")
                    .queryParam("state", UUID.randomUUID().toString()) // CSRF 방지
                    .build().toUriString();

            response.sendRedirect(authorizeUrl);
        } catch (Exception e) {
            log.error("❌ 로그인 리다이렉트 실패: {}", e.getMessage());
        }
    }


    /**
     * 4️⃣ SPA → BFF (로그인 상태 확인)
     * SPA가 리다이렉트된 후 로그인 상태를 확인
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus(HttpServletRequest request) {
        Map<String, Object> result = new HashMap<>();

        try {
            String sessionId = getSessionIdFromCookie(request);
            if (sessionId == null) {
                result.put("authenticated", false);
                result.put("message", "세션 없음");
                return ResponseEntity.ok(result);
            }

            String accessToken = tokenService.getAccessToken(sessionId);
            if (accessToken == null) {
                result.put("authenticated", false);
                result.put("message", "토큰 없음");
                return ResponseEntity.ok(result);
            }

            result.put("authenticated", true);
            result.put("message", "인증됨");
            result.put("sessionId", sessionId);
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("❌ 상태 확인 실패: {}", e.getMessage());
            result.put("authenticated", false);
            result.put("error", e.getMessage());
            return ResponseEntity.ok(result);
        }
    }

    /**
     * 사용자 정보 반환
     */
    @GetMapping("/user/me")
    public ResponseEntity<Map<String, Object>> getUserInfo(HttpServletRequest request) {
        Map<String, Object> result = new HashMap<>();

        try {
            String sessionId = getSessionIdFromCookie(request);
            if (sessionId == null) {
                result.put("success", false);
                result.put("error", "세션 없음");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
            }

            String accessToken = tokenService.getAccessToken(sessionId);
            if (accessToken == null) {
                result.put("success", false);
                result.put("error", "토큰 없음");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
            }

            // Auth Server에서 사용자 정보 조회
            Map<String, Object> userInfo = tokenService.getUserInfo(accessToken);
            if (userInfo == null) {
                result.put("success", false);
                result.put("error", "사용자 정보 조회 실패");
                return ResponseEntity.badRequest().body(result);
            }

            result.put("success", true);
            result.put("user", userInfo);
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("❌ 사용자 정보 조회 실패: {}", e.getMessage());
            result.put("success", false);
            result.put("error", e.getMessage());
            return ResponseEntity.internalServerError().body(result);
        }
    }

    /**
     * 로그아웃 처리
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request, HttpServletResponse response) {
        Map<String, Object> result = new HashMap<>();

        try {
            String sessionId = getSessionIdFromCookie(request);
            if (sessionId != null) {
                tokenService.deleteSession(sessionId);

                // 쿠키 삭제
                Cookie sessionCookie = new Cookie("SESSION_ID", null);
                sessionCookie.setHttpOnly(true);
                sessionCookie.setPath("/");
                sessionCookie.setMaxAge(0);
                response.addCookie(sessionCookie);
            }

            result.put("success", true);
            result.put("message", "로그아웃 성공");
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("❌ 로그아웃 실패: {}", e.getMessage());
            result.put("success", false);
            result.put("error", e.getMessage());
            return ResponseEntity.internalServerError().body(result);
        }
    }

    /**
     * 쿠키에서 세션 ID 추출
     */
    private String getSessionIdFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("SESSION_ID".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}

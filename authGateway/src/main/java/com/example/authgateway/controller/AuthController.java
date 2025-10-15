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

    private final WebClient webClient = WebClient.create();

    /**
     * Auth Server → BFF callback
     */
    @GetMapping("/callback")
    public ResponseEntity<?> callback(
            @RequestParam("code") String code,
            HttpServletResponse response
    ) {
        try {
            // 1️⃣ Auth Server로 토큰 교환 요청
            Map<String, String> tokenResponse = webClient.post()
                    .uri("http://localhost:9090/oauth2/token")
                    .headers(headers -> headers.setBasicAuth("bff-client", "bff-secret"))
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                            .with("code", code)
                            .with("redirect_uri", "http://localhost:9091/api/auth/callback"))
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {})
                    .block();

            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("success", false, "error", "토큰 응답 없음"));
            }

            String accessToken = tokenResponse.get("access_token");
            String refreshToken = tokenResponse.get("refresh_token");

            // 2️⃣ Redis에 세션 저장
            String sessionId = UUID.randomUUID().toString();
            TokenResponse tokenObj = new TokenResponse();
            tokenObj.setAccessToken(accessToken);
            tokenObj.setRefreshToken(refreshToken);
            tokenObj.setTokenType(tokenResponse.get("token_type"));
            tokenObj.setExpiresIn(Long.valueOf(tokenResponse.get("expires_in")));
            tokenObj.setScope(tokenResponse.get("scope"));

            tokenService.saveToken(sessionId, tokenObj); // Redis 저장 로직

            // 3️⃣ SPA에 sessionId 쿠키 전달
            Cookie sessionCookie = new Cookie("SESSION_ID", sessionId);
            sessionCookie.setHttpOnly(true);
            sessionCookie.setPath("/");
            sessionCookie.setMaxAge(7 * 24 * 60 * 60); // 7일
            response.addCookie(sessionCookie);

            return ResponseEntity.ok(Map.of("success", true, "message", "로그인 성공"));

        } catch (Exception e) {
            log.error("❌ 로그인 콜백 처리 실패: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    /**
     * SPA → BFF → API 요청
     */
    @GetMapping("/userinfo")
    public ResponseEntity<?> userinfo(@CookieValue("ACCESS_TOKEN") String token) {
        Map<String, Object> userinfo = webClient.get()
                .uri("http://localhost:9090/userinfo")
                .headers(h -> h.setBearerAuth(token))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();

        return ResponseEntity.ok(userinfo);
    }

    /**
     * 1️⃣ SPA → BFF → Auth Server (Authorization Request)
     * SPA가 로그인 버튼 클릭 → BFF 서버의 /login으로 리다이렉트
     * BFF 서버가 Auth Server의 OAuth2 Client로 동작
     */
    @GetMapping("/login")
    public void login(HttpServletResponse response) {
        try {
            String authorizeUrl = UriComponentsBuilder.fromUriString("http://localhost:9090/oauth2/authorize")
                    .queryParam("response_type", "code")
                    .queryParam("client_id", "bff-client")
                    .queryParam("redirect_uri", "http://localhost:9091/api/auth/callback")
                    .queryParam("scope", "openid profile email")
                    .build().toUriString();

            response.sendRedirect(authorizeUrl);
        } catch (Exception e) {
            log.error("❌ 로그인 리다이렉트 실패: {}", e.getMessage());
        }
    }


    /**
     * 4️⃣ SPA → BFF → API 서버 (Access)
     * SPA는 로그인 후 BFF의 엔드포인트 호출 (예: /api/user/me)
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
                // Refresh Token으로 토큰 갱신 시도
                String refreshToken = tokenService.getRefreshToken(sessionId);
                if (refreshToken != null) {
                    TokenResponse newTokenResponse = tokenService.refreshToken(refreshToken);
                    if (newTokenResponse != null) {
                        tokenService.saveToken(sessionId, newTokenResponse);
                        accessToken = newTokenResponse.getAccessToken();
                    }
                }
            }

            if (accessToken == null) {
                result.put("authenticated", false);
                result.put("message", "토큰 없음");
                return ResponseEntity.ok(result);
            }

            result.put("authenticated", true);
            result.put("message", "인증됨");
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

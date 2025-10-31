package com.example.webbffserver.controller;


import com.example.constants.ErrorCode;
import com.example.constants.LoginResult;
import com.example.webbffserver.config.AppProperties;
import com.example.webbffserver.dto.TokenResponse;
import com.example.webbffserver.service.TokenService;
import com.example.webbffserver.utils.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static com.example.webbffserver.utils.CookieUtil.ACCESS_TOKEN_COOKIE;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final AppProperties appProperties;
    private final WebClient webClient;

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
                response.sendRedirect(buildFrontendRedirectUrl(LoginResult.FAILED,error));
                return;
            }

            // 2️⃣ Authorization Code 체크
            if (code == null) {
                log.error("❌ Authorization Code 없음");
                response.sendRedirect(buildFrontendRedirectUrl(LoginResult.FAILED, ErrorCode.NO_AUTHORIZATION_CODE));
                return;
            }

            // 3️⃣ Authorization Code로 토큰 교환 (Spring Security OAuth2 Authorization Server 사용)
            TokenResponse tokenResponse = tokenService.exchangeToken(code);

            if (tokenResponse == null) {
                log.error("❌ 토큰 교환 실패");
                response.sendRedirect(buildFrontendRedirectUrl(LoginResult.FAILED, ErrorCode.TOKEN_EXCHANGE_FAILED));
                return;
            }

            // 4️⃣ 토큰을 세션으로 저장
            //String sessionId = UUID.randomUUID().toString();
            //tokenService.saveToken(sessionId, tokenResponse);

            String accessToken = tokenResponse.getAccessToken();
            String refreshToken = tokenResponse.getRefreshToken();

            // JWT를 HttpOnly 쿠키에 저장
            CookieUtil.addTokenCookies(response, accessToken, refreshToken, /*secure*/ false);

            log.info("✅ 토큰 쿠키 저장 완료 (Access={}, Refresh={})", accessToken != null, refreshToken != null);

            // 5️⃣ SPA로 성공 리다이렉트
            response.sendRedirect(buildFrontendRedirectUrl(LoginResult.SUCCESS, null));

        } catch (Exception e) {
            log.error("❌ 로그인 콜백 처리 실패: {}", e.getMessage(), e);
            try {
                response.sendRedirect(buildFrontendRedirectUrl(LoginResult.FAILED, ErrorCode.CALL_BACK_FAILED));
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

            String accessToken = CookieUtil.getCookie(request, ACCESS_TOKEN_COOKIE);
            if (accessToken != null) {
                // 이미 로그인된 상태 - SPA로 리다이렉트
                response.sendRedirect(buildFrontendRedirectUrl(LoginResult.ALREADY, null));
                return;
            }

            // 2️⃣ 세션이 없으면 OAuth2 Authorization Server로 리다이렉트
            String authorizeUrl = UriComponentsBuilder.fromUriString(appProperties.getAuthServerAuthorizeUrl())
                    .queryParam("response_type", "code")
                    .queryParam("client_id", "bff-client")
                    .queryParam("redirect_uri", appProperties.getAuthGatewayCallbackUrl())
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

            String accessToken = CookieUtil.getCookie(request, ACCESS_TOKEN_COOKIE);
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

            String accessToken = CookieUtil.getCookie(request, ACCESS_TOKEN_COOKIE);

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
            // 1️⃣ 토큰 쿠키 추출
            String refreshToken = CookieUtil.getCookie(request, "REFRESH_TOKEN");

            // 2️⃣ 쿠키 제거
            CookieUtil.clearTokenCookies(response, /*secure*/ false);

            // 3️⃣ Auth Server에 RefreshToken 폐기 요청 (RFC7009 /oauth2/revoke)
            if (refreshToken != null) {
                webClient.post()
                        .uri(appProperties.getAuthServerRevokeUrl())
                        .headers(h -> {
                            h.setBasicAuth("bff-client", "bff-secret"); // 클라이언트 인증
                            h.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                        })
                        .body(BodyInserters.fromFormData("token", refreshToken)
                                .with("token_type_hint", "refresh_token"))
                        .retrieve()
                        .toBodilessEntity()
                        .block();

                log.info("✅ Auth Server에 RefreshToken revoke 요청 완료");
            }

            // 4️⃣ 응답 반환
            result.put("success", true);
            result.put("message", "로그아웃 완료");
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            log.error("❌ 로그아웃 중 오류: {}", e.getMessage());
            result.put("success", false);
            result.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
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

    private String getAuthServerSessionIdFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("JSESSIONID".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private String buildFrontendRedirectUrl(String status, String error) {
        String url = appProperties.getFrontendUrl() + "?login=" + status;
        if (error != null) {
            url += "&error=" + error;
        }
        return url;
    }

}

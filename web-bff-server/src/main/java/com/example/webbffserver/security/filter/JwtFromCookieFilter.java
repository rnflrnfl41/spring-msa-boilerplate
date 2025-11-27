package com.example.webbffserver.security.filter;

import com.example.webbffserver.security.request.MutableHttpServletRequest;
import com.example.webbffserver.service.TokenService;
import com.example.webbffserver.utils.CookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

import static com.example.webbffserver.utils.CookieUtil.ACCESS_TOKEN_COOKIE;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFromCookieFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    private static final List<String> EXCLUDED_PATHS = List.of(
            "/api/auth/login",
            "/api/auth/logout",
            "/api/auth/refresh",
            "/api/auth/callback",
            "/oauth2",
            "/public",
            "/.well-known"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        String path = req.getRequestURI();
        // 예외 경로면 토큰 자동 주입하지 않음
        if (EXCLUDED_PATHS.stream().anyMatch(path::startsWith)) {
            chain.doFilter(req, res);
            return;
        }

        // Authorization 헤더가 없으면 쿠키에서 토큰 가져오기
        String accessToken = null;
        if (req.getHeader("Authorization") == null) {
            accessToken = CookieUtil.getCookie(req, ACCESS_TOKEN_COOKIE);
        } else {
            // Authorization 헤더가 있으면 Bearer 제거하고 토큰만 추출
            String authHeader = req.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                accessToken = authHeader.substring(7);
            }
        }

        // 토큰이 있고 만료되었으면 자동 갱신
        if (accessToken != null && tokenService.isTokenExpired(accessToken)) {
            log.info("🔄 AccessToken 만료 감지, 자동 갱신 시도: {}", path);
            boolean refreshed = tokenService.refreshToken(req, res);
            if (refreshed) {
                // 새 토큰으로 교체
                accessToken = CookieUtil.getCookie(req, ACCESS_TOKEN_COOKIE);
                log.info("✅ 토큰 갱신 성공, 요청 재시도: {}", path);
            } else {
                log.error("❌ 토큰 갱신 실패: {}", path);
                res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token expired and refresh failed");
                return;
            }
        }

        // Authorization 헤더에 토큰 추가 (없는 경우만)
        if (req.getHeader("Authorization") == null && accessToken != null) {
            MutableHttpServletRequest mutableReq = new MutableHttpServletRequest(req);
            mutableReq.putHeader("Authorization", "Bearer " + accessToken);
            req = mutableReq;
        }

        chain.doFilter(req, res);
    }
}

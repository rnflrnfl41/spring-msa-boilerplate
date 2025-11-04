package com.example.webbffserver.security.filter;

import com.example.webbffserver.security.request.MutableHttpServletRequest;
import com.example.webbffserver.utils.CookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

import static com.example.webbffserver.utils.CookieUtil.ACCESS_TOKEN_COOKIE;

/*@Component
public class JwtFromCookieFilter extends OncePerRequestFilter {

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

        if (req.getHeader("Authorization") == null) {
            String token = CookieUtil.getCookie(req, ACCESS_TOKEN_COOKIE);
            if (token != null) {
                req = new MutableHttpServletRequest(req);
                ((MutableHttpServletRequest) req).putHeader("Authorization", "Bearer " + token);
            }
        }
        chain.doFilter(req, res);
    }
}*/

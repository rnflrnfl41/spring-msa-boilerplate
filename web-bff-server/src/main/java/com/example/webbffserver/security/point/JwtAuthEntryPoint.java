package com.example.webbffserver.security.point;

import com.example.http.CustomHttpStatus;
import com.example.webbffserver.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthEntryPoint implements AuthenticationEntryPoint {

    private final TokenService tokenService;

    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException ex)
            throws IOException {

        // JWT 만료 or 검증 실패 감지
        if (ex.getCause() instanceof JwtValidationException) {
            String newToken = tokenService.refreshToken(req, res);
            if (newToken != null) {
                res.setStatus(CustomHttpStatus.RETRY_WITH.getCode());
                res.getWriter().write("Token refreshed. Please retry your request.");
                return;
            }
        }

        // 실패 응답
        res.sendError(HttpStatus.UNAUTHORIZED.value(), "Access Token expired or invalid");
    }
}

package com.example.authserver.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class FormLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        
        log.info("폼 로그인 성공: {}", authentication.getName());
        
        // 저장된 요청(원래의 authorization request) 복원
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        
        if (savedRequest != null) {

            String redirectUrl = savedRequest.getRedirectUrl();

            if (redirectUrl.contains("/error")) {
                log.warn("비정상 redirect 감지, 기본 페이지로 이동: {}", redirectUrl);
                super.onAuthenticationSuccess(request, response, authentication);
                return;
            }

            // 원래의 authorization request로 리다이렉트
            log.info("저장된 OAuth2 authorization request로 리다이렉트: {}", redirectUrl);
            getRedirectStrategy().sendRedirect(request, response, redirectUrl);
        } else {
            // 저장된 요청이 없으면 기본 페이지로 리다이렉트
            log.info("저장된 요청 없음, 기본 페이지로 리다이렉트");
            super.onAuthenticationSuccess(request, response, authentication);
        }
    }
}

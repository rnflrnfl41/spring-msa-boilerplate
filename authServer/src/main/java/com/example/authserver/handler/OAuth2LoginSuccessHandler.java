package com.example.authserver.handler;

import com.example.Constants.Constants;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Slf4j
@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        String baseRedirectUrl = Constants.getFrontendDashBoardUrl();
        
        log.info("OAuth2 로그인 성공: {}", authentication.getName());
        
        // OIDC 사용자 정보 로깅
        if (authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            log.info("OIDC 사용자 정보 - Subject: {}, Email: {}, Name: {}", 
                    oidcUser.getSubject(), oidcUser.getEmail(), oidcUser.getFullName());
        }

        // 저장된 요청(원래의 authorization request) 복원
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        
        if (savedRequest != null) {
            String redirectUrl = savedRequest.getRedirectUrl();
            log.info("저장된 요청으로 리다이렉트: {}", redirectUrl);
            
            // 원래의 authorization request로 리다이렉트
            getRedirectStrategy().sendRedirect(request, response, redirectUrl);
        } else {
            // 저장된 요청이 없으면 기본 페이지로 리다이렉트
            log.info("저장된 요청 없음, 기본 페이지로 리다이렉트");
            getRedirectStrategy().sendRedirect(request, response, baseRedirectUrl);
            super.onAuthenticationSuccess(request, response, authentication);
        }
    }
}

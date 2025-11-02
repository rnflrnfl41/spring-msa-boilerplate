package com.example.authserver.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.stereotype.Component;

@Component
public class CustomRequestCache extends HttpSessionRequestCache {

    private static final String[] IGNORED_PATHS = {
            "/.well-known/appspecific/",
            "/favicon.ico",
            "/manifest.json"
    };

    @Override
    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
        String uri = request.getRequestURI();
        for (String ignore : IGNORED_PATHS) {
            if (uri.startsWith(ignore)) {
                // Chrome devtools 등의 자동 요청은 무시
                return;
            }
        }
        super.saveRequest(request, response);
    }
}
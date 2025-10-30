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

import static com.example.webbffserver.utils.CookieUtil.ACCESS_TOKEN_COOKIE;

@Component
public class JwtFromCookieFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        if (req.getHeader("Authorization") == null) {
            String token = CookieUtil.getCookie(req, ACCESS_TOKEN_COOKIE);
            if (token != null) {
                req = new MutableHttpServletRequest(req);
                ((MutableHttpServletRequest) req).putHeader("Authorization", "Bearer " + token);
            }
        }
        chain.doFilter(req, res);
    }
}

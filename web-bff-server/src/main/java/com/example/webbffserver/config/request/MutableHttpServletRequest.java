package com.example.webbffserver.config.request;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.util.*;

public class MutableHttpServletRequest extends HttpServletRequestWrapper {
    private final Map<String, String> customHeaders = new HashMap<>();
    public MutableHttpServletRequest(HttpServletRequest request) { super(request); }
    public void putHeader(String name, String value) { customHeaders.put(name, value); }
    @Override public String getHeader(String name) {
        String val = customHeaders.get(name);
        return val != null ? val : super.getHeader(name);
    }
    @Override public Enumeration<String> getHeaders(String name) {
        String val = customHeaders.get(name);
        if (val != null) return Collections.enumeration(List.of(val));
        return super.getHeaders(name);
    }
}

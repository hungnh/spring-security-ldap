package com.higgsup.security.constants;

public class SecurityConstants {

    // Endpoints
    public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";
    public static final String LOGIN_ENTRY_POINT = "/api/auth/login";
    public static final String TOKEN_REFRESH_ENTRY_POINT = "/api/auth/token";
    public static final String TOKEN_INVALIDATE_ENTRY_POINT = "/api/auth/token/invalidate";

    // Requests
    public static final String AUTHORIZATION_HEADER_PREFIX = "Bearer ";

    // JWT
    public static final String JWT_SCOPE_CLAIM = "scopes";
}

package com.higgsup.common.exceptions;

public class ErrorMessage {
    // Authentication errors
    public static final String INVALID_USER_NAME_OR_PASSWORD = "Authentication Failed. Username or Password not valid.";
    public static final String MISSING_AUTHORIZATION_HEADER = "Authorization header cannot be blank.";
    public static final String AUTHORIZATION_HEADER_INVALID = "Authorization header is invalid.";
    public static final String MISSING_USER_NAME_OR_PASSWORD = "Username or Password not provided.";
    public static final String AUTHENTICATION_FAILED = "Authentication failed.";
    public static final String USER_HAS_NO_ROLES = "User has no roles assigned.";
    public static final String USERNAME_NOT_FOUND = "User not found: ";
    public static final String AUTHENTICATION_METHOD_NOT_SUPPORTED = "Authentication method not supported.";
    public static final String NO_AUTHENTICATION_DATA_PROVIDED = "No authentication data provided.";
    public static final String TOKEN_EXPIRED = "Token has expired.";
    public static final String TOKEN_INVALID = "Token is invalid.";
    public static final String REFRESH_TOKEN_INVALID = "Refresh token is invalid.";
    public static final String MISSING_USERNAME_TO_GENERATE_TOKEN = "Can not create JWT token without username.";
}

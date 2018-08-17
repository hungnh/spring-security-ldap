package com.higgsup.security.config.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.higgsup.common.exceptions.ErrorCode;
import com.higgsup.common.exceptions.ErrorMessage;
import com.higgsup.common.exceptions.ErrorResponse;
import com.higgsup.security.exceptions.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AuthenticationExceptionFailureHandler implements AuthenticationFailureHandler {
    private final ObjectMapper objectMapper;

    @Autowired
    public AuthenticationExceptionFailureHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException authException)
            throws IOException, ServletException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        if (authException instanceof BadCredentialsException || authException instanceof UsernameNotFoundException) {
            objectMapper.writeValue(
                    response.getWriter(),
                    ErrorResponse.of(ErrorMessage.INVALID_USER_NAME_OR_PASSWORD, ErrorCode.BAD_CREDENTIALS, HttpStatus.UNAUTHORIZED)
            );
        } else if (authException instanceof JwtExpiredTokenException) {
            objectMapper.writeValue(
                    response.getWriter(),
                    ErrorResponse.of(authException.getMessage(), ErrorCode.ACCESS_TOKEN_EXPIRED, HttpStatus.UNAUTHORIZED)
            );
        } else if (authException instanceof JwtInvalidTokenException) {
            objectMapper.writeValue(
                    response.getWriter(),
                    ErrorResponse.of(authException.getMessage(), ErrorCode.ACCESS_TOKEN_INVALID, HttpStatus.UNAUTHORIZED)
            );
        } else if (authException instanceof AuthenticationMethodNotSupportedException) {
            objectMapper.writeValue(
                    response.getWriter(),
                    ErrorResponse.of(authException.getMessage(), ErrorCode.AUTHENTICATION_FAILED, HttpStatus.UNAUTHORIZED)
            );
        } else if (authException instanceof AuthenticationServiceException) {
            objectMapper.writeValue(
                    response.getWriter(),
                    ErrorResponse.of(authException.getMessage(), ErrorCode.AUTHENTICATION_FAILED, HttpStatus.UNAUTHORIZED)
            );
        } else {
            objectMapper.writeValue(
                    response.getWriter(),
                    ErrorResponse.of(ErrorMessage.AUTHENTICATION_FAILED, ErrorCode.AUTHENTICATION_FAILED, HttpStatus.UNAUTHORIZED)
            );
        }

    }
}

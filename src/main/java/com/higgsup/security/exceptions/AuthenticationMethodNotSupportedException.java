package com.higgsup.security.exceptions;

import org.springframework.security.authentication.AuthenticationServiceException;

public class AuthenticationMethodNotSupportedException extends AuthenticationServiceException {

    private static final long serialVersionUID = -680546432603022097L;

    public AuthenticationMethodNotSupportedException(String msg) {
        super(msg);
    }
}

package com.higgsup.security.exceptions;

import com.higgsup.security.jwt.token.JwtToken;
import org.springframework.security.core.AuthenticationException;

public class JwtInvalidTokenException extends AuthenticationException {

    private static final long serialVersionUID = -7372211425291595155L;

    private JwtToken token;

    public JwtInvalidTokenException(String msg) {
        super(msg);
    }

    public JwtInvalidTokenException(JwtToken token, String msg, Throwable t) {
        super(msg, t);
        this.token = token;
    }

    public String token() {
        return this.token.getToken();
    }
}

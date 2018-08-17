package com.higgsup.security.jwt.verifier;

public interface TokenVerifier {
    boolean verify(String jti);
}

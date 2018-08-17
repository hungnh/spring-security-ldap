package com.higgsup.security.jwt.storage;


import com.higgsup.security.jwt.token.JwtToken;

public interface TokenStore {
    void store(JwtToken jwtToken);

    JwtToken retrieve(String jti);

    boolean isPresent(String jti);

}

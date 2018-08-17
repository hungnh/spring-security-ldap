package com.higgsup.security.jwt.token;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.jsonwebtoken.Claims;

public class JwtAccessToken implements JwtToken {
    private final String rawToken;
    private Claims claims;

    public JwtAccessToken(final String rawToken, Claims claims) {
        this.rawToken = rawToken;
        this.claims = claims;
    }

    @Override
    public String getToken() {
        return rawToken;
    }

    @JsonIgnore
    public Claims getClaims() {
        return claims;
    }

    @Override
    @JsonIgnore
    public String getJti() {
        return claims.getId();
    }
}

package com.higgsup.security.jwt.token;

import com.higgsup.security.constants.SecurityConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

import java.util.List;

public class RefreshToken implements JwtToken {

    private Jws<Claims> claims;

    private RefreshToken(Jws<Claims> claims) {
        this.claims = claims;
    }

    public static RefreshToken create(RawJwtToken token, String signingKey) {
        Jws<Claims> claims = token.parseClaims(signingKey);
        List<String> scopes = claims.getBody().get(SecurityConstants.JWT_SCOPE_CLAIM, List.class);
        if (scopes == null || scopes.isEmpty() || !scopes.contains(Scope.REFRESH_TOKEN.authority())) {
            return null;
        }
        return new RefreshToken(claims);
    }

    @Override
    public String getToken() {
        return null;
    }

    public Jws<Claims> getClaims() {
        return claims;
    }

    public String getJti() {
        return claims.getBody().getId();
    }

    public String getSubject() {
        return claims.getBody().getSubject();
    }
}

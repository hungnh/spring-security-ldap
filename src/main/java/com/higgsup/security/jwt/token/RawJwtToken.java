package com.higgsup.security.jwt.token;

import com.higgsup.common.exceptions.ErrorMessage;
import com.higgsup.security.exceptions.JwtExpiredTokenException;
import com.higgsup.security.exceptions.JwtInvalidTokenException;
import io.jsonwebtoken.*;

public class RawJwtToken implements JwtToken {
    private String token;

    public RawJwtToken(String token) {
        this.token = token;
    }

    public Jws<Claims> parseClaims(String signingKey) {
        try {
            return Jwts.parser().setSigningKey(signingKey).parseClaimsJws(this.token);
        } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException | SignatureException ex) {
            throw new JwtInvalidTokenException(this, ErrorMessage.TOKEN_INVALID, ex);
        } catch (ExpiredJwtException expiredEx) {
            throw new JwtExpiredTokenException(this, ErrorMessage.TOKEN_EXPIRED, expiredEx);
        }
    }

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public String getJti() {
        return null;
    }
}

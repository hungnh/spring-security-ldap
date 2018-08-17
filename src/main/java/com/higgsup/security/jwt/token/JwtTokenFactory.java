package com.higgsup.security.jwt.token;

import com.higgsup.security.constants.SecurityConstants;
import com.higgsup.common.exceptions.ErrorMessage;
import com.higgsup.security.jwt.JwtSettings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtTokenFactory {

    private final JwtSettings jwtSettings;

    public JwtTokenFactory(JwtSettings jwtSettings) {
        this.jwtSettings = jwtSettings;
    }

    public JwtToken createJwtAccessToken(UserDetails user) {
        if (StringUtils.isEmpty(user.getUsername())) {
            throw new IllegalArgumentException(ErrorMessage.MISSING_USERNAME_TO_GENERATE_TOKEN);
        }

        if (user.getAuthorities() == null || user.getAuthorities().isEmpty()) {
            throw new IllegalArgumentException(ErrorMessage.USER_HAS_NO_ROLES);
        }

        Claims claims = Jwts.claims().setSubject(user.getUsername());

        List<String> scopes = user.getAuthorities().stream().map(Object::toString).collect(Collectors.toList());
        claims.put(SecurityConstants.JWT_SCOPE_CLAIM, scopes);

        Date now = new Date();
        Date tokenExpiredAt = new Date(now.getTime() + jwtSettings.getTokenExpTime() * 1000L);

        String token = Jwts.builder()
                .setClaims(claims)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(now)
                .setExpiration(tokenExpiredAt)
                .signWith(SignatureAlgorithm.HS512, jwtSettings.getTokenSigningKey())
                .compact();

        return new JwtAccessToken(token, claims);
    }

    public JwtToken createJwtRefreshToken(UserDetails user) {
        if (StringUtils.isEmpty(user.getUsername())) {
            throw new IllegalArgumentException(ErrorMessage.MISSING_USERNAME_TO_GENERATE_TOKEN);
        }

        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put(SecurityConstants.JWT_SCOPE_CLAIM, Collections.singletonList(Scope.REFRESH_TOKEN.authority()));

        Date now = new Date();
        Date tokenExpiredAt = new Date(now.getTime() + jwtSettings.getRefreshTokenExpTime() * 1000L);

        String token = Jwts.builder()
                .setClaims(claims)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(now)
                .setExpiration(tokenExpiredAt)
                .signWith(SignatureAlgorithm.HS512, jwtSettings.getTokenSigningKey())
                .compact();

        return new JwtAccessToken(token, claims);
    }
}

package com.higgsup.security.config.provider;

import com.higgsup.common.exceptions.ErrorMessage;
import com.higgsup.security.constants.SecurityConstants;
import com.higgsup.security.jwt.JwtSettings;
import com.higgsup.security.jwt.token.JwtAuthenticationToken;
import com.higgsup.security.jwt.token.RawJwtToken;
import com.higgsup.security.jwt.verifier.TokenVerifier;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtSettings jwtSettings;

    @Autowired
    public JwtAuthenticationProvider(JwtSettings jwtSettings,
                                     TokenVerifier tokenVerifier) {
        this.jwtSettings = jwtSettings;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.notNull(authentication, ErrorMessage.NO_AUTHENTICATION_DATA_PROVIDED);

        RawJwtToken rawJwtToken = (RawJwtToken) authentication.getCredentials();
        Jws<Claims> jwsClaims = rawJwtToken.parseClaims(jwtSettings.getTokenSigningKey());

        String username = jwsClaims.getBody().getSubject();
        List<String> scopes = jwsClaims.getBody().get(SecurityConstants.JWT_SCOPE_CLAIM, List.class);
        List<GrantedAuthority> authorities = scopes.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        UserDetails authenticatedUser = new User(username, null, authorities);

        return new JwtAuthenticationToken(authenticatedUser, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

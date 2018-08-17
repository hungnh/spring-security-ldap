package com.higgsup.security.config.provider;

import com.higgsup.common.exceptions.ErrorMessage;
import com.higgsup.security.constants.SecurityConstants;
import com.higgsup.security.exceptions.JwtInvalidTokenException;
import com.higgsup.security.jwt.JwtSettings;
import com.higgsup.security.jwt.token.JwtAuthenticationToken;
import com.higgsup.security.jwt.token.RawJwtToken;
import com.higgsup.security.jwt.verifier.TokenVerifier;
import com.higgsup.security.ldap.LdapUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtSettings jwtSettings;
    private final TokenVerifier tokenVerifier;
    private final LdapUserSearch ldapUserSearch;
    private final LdapUserDetailsMapper ldapUserDetailsMapper;

    @Autowired
    public JwtAuthenticationProvider(JwtSettings jwtSettings,
                                     TokenVerifier tokenVerifier,
                                     LdapUserSearch ldapUserSearch,
                                     LdapUserDetailsMapper ldapUserDetailsMapper) {
        this.jwtSettings = jwtSettings;
        this.tokenVerifier = tokenVerifier;
        this.ldapUserSearch = ldapUserSearch;
        this.ldapUserDetailsMapper = ldapUserDetailsMapper;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RawJwtToken rawJwtToken = (RawJwtToken) authentication.getCredentials();
        Jws<Claims> jwsClaims = rawJwtToken.parseClaims(jwtSettings.getTokenSigningKey());

        String jti = jwsClaims.getBody().getId();
        if (!tokenVerifier.verify(jti)) {
            throw new JwtInvalidTokenException(ErrorMessage.TOKEN_INVALID);
        }

        String username = jwsClaims.getBody().getSubject();
        DirContextOperations userContext = ldapUserSearch.searchForUser(username);

        Date lastPasswordResetDate = LdapUtils.getLastPasswordResetDateFromContext(userContext);
        Date tokenCreatedDate = jwsClaims.getBody().getIssuedAt();

        if (lastPasswordResetDate != null && tokenCreatedDate.before(lastPasswordResetDate)) {
            throw new JwtInvalidTokenException(ErrorMessage.TOKEN_INVALID);
        }

        List<String> scopes = jwsClaims.getBody().get(SecurityConstants.JWT_SCOPE_CLAIM, List.class);
        List<GrantedAuthority> authorities = scopes.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        UserDetails userDetails = ldapUserDetailsMapper.mapUserFromContext(userContext, username, authorities);

        return new JwtAuthenticationToken(userDetails, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

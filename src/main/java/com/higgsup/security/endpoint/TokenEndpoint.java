package com.higgsup.security.endpoint;

import com.higgsup.common.exceptions.ErrorMessage;
import com.higgsup.dto.GenericResponseDTO;
import com.higgsup.security.exceptions.JwtInvalidTokenException;
import com.higgsup.security.jwt.JwtSettings;
import com.higgsup.security.jwt.extractor.TokenExtractor;
import com.higgsup.security.jwt.storage.TokenStore;
import com.higgsup.security.jwt.token.*;
import com.higgsup.security.jwt.verifier.TokenVerifier;
import com.higgsup.security.ldap.LdapUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Date;

import static com.higgsup.security.constants.SecurityConstants.TOKEN_INVALIDATE_ENTRY_POINT;
import static com.higgsup.security.constants.SecurityConstants.TOKEN_REFRESH_ENTRY_POINT;

@RestController
public class TokenEndpoint {

    private final JwtSettings jwtSettings;
    private final TokenExtractor tokenExtractor;
    private final JwtTokenFactory tokenFactory;
    private final TokenStore invalidTokenStore;
    private final TokenVerifier tokenVerifier;
    private final LdapUserSearch ldapUserSearch;
    private final LdapAuthoritiesPopulator ldapAuthoritiesPopulator;
    private final LdapUserDetailsMapper ldapUserDetailsMapper;

    public TokenEndpoint(JwtSettings jwtSettings,
                         TokenExtractor tokenExtractor,
                         JwtTokenFactory tokenFactory,
                         TokenStore invalidTokenStore,
                         TokenVerifier tokenVerifier,
                         LdapUserSearch ldapUserSearch,
                         LdapAuthoritiesPopulator ldapAuthoritiesPopulator,
                         LdapUserDetailsMapper ldapUserDetailsMapper) {
        this.jwtSettings = jwtSettings;
        this.tokenExtractor = tokenExtractor;
        this.tokenFactory = tokenFactory;
        this.invalidTokenStore = invalidTokenStore;
        this.tokenVerifier = tokenVerifier;
        this.ldapUserSearch = ldapUserSearch;
        this.ldapAuthoritiesPopulator = ldapAuthoritiesPopulator;
        this.ldapUserDetailsMapper = ldapUserDetailsMapper;
    }

    @GetMapping(TOKEN_REFRESH_ENTRY_POINT)
    public JwtToken refreshToken(HttpServletRequest request) {
        String tokenPayload = tokenExtractor.extract(request.getHeader(jwtSettings.getRequestHeader()));

        RawJwtToken rawJwtToken = new RawJwtToken(tokenPayload);
        RefreshToken refreshToken = RefreshToken.create(rawJwtToken, jwtSettings.getTokenSigningKey());
        if (refreshToken == null) {
            throw new JwtInvalidTokenException(rawJwtToken, ErrorMessage.REFRESH_TOKEN_INVALID, null);
        }

        String jti = refreshToken.getJti();
        if (!tokenVerifier.verify(jti)) {
            throw new JwtInvalidTokenException(rawJwtToken, ErrorMessage.REFRESH_TOKEN_INVALID, null);
        }

        String username = refreshToken.getSubject();

        DirContextOperations userContext = ldapUserSearch.searchForUser(username);
        Collection<? extends GrantedAuthority> roles = ldapAuthoritiesPopulator.getGrantedAuthorities(userContext, username);
        if (roles == null || roles.isEmpty()) {
            throw new InsufficientAuthenticationException(ErrorMessage.USER_HAS_NO_ROLES);
        }

        Jws<Claims> claims = refreshToken.getClaims();
        Date tokenCreatedDate = claims.getBody().getIssuedAt();
        Date lastPasswordResetDate = LdapUtils.getLastPasswordResetDateFromContext(userContext);
        if (lastPasswordResetDate != null && tokenCreatedDate.before(lastPasswordResetDate)) {
            throw new JwtInvalidTokenException(rawJwtToken, ErrorMessage.REFRESH_TOKEN_INVALID, null);
        }

        UserDetails userDetails = ldapUserDetailsMapper.mapUserFromContext(userContext, username, roles);

        return tokenFactory.createJwtAccessToken(userDetails);
    }

    @PostMapping(TOKEN_INVALIDATE_ENTRY_POINT)
    public GenericResponseDTO invalidateToken(HttpServletRequest request) {
        String tokenPayload = tokenExtractor.extract(request.getHeader(jwtSettings.getRequestHeader()));

        RawJwtToken rawJwtToken = new RawJwtToken(tokenPayload);
        Jws<Claims> jwsClaims = rawJwtToken.parseClaims(jwtSettings.getTokenSigningKey());

        JwtToken storedToken = new JwtAccessToken(rawJwtToken.getToken(), jwsClaims.getBody());
        invalidTokenStore.store(storedToken);

        return GenericResponseDTO.success();
    }

}

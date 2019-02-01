package com.higgsup.security.endpoint;

import com.higgsup.common.exceptions.ErrorMessage;
import com.higgsup.dto.GenericResponseDTO;
import com.higgsup.security.entity.AppUser;
import com.higgsup.security.exceptions.JwtInvalidTokenException;
import com.higgsup.security.jwt.JwtSettings;
import com.higgsup.security.jwt.extractor.TokenExtractor;
import com.higgsup.security.jwt.storage.TokenStore;
import com.higgsup.security.jwt.token.*;
import com.higgsup.security.jwt.verifier.TokenVerifier;
import com.higgsup.security.user.IUserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

import static com.higgsup.security.constants.SecurityConstants.TOKEN_INVALIDATE_ENTRY_POINT;
import static com.higgsup.security.constants.SecurityConstants.TOKEN_REFRESH_ENTRY_POINT;

@RestController
public class TokenEndpoint {

    private final JwtSettings jwtSettings;
    private final TokenExtractor tokenExtractor;
    private final JwtTokenFactory tokenFactory;
    private final TokenStore invalidTokenStore;
    private final TokenVerifier tokenVerifier;
    private final IUserService userService;

    public TokenEndpoint(JwtSettings jwtSettings,
                         TokenExtractor tokenExtractor,
                         JwtTokenFactory tokenFactory,
                         TokenStore invalidTokenStore,
                         TokenVerifier tokenVerifier,
                         IUserService userService) {
        this.jwtSettings = jwtSettings;
        this.tokenExtractor = tokenExtractor;
        this.tokenFactory = tokenFactory;
        this.invalidTokenStore = invalidTokenStore;
        this.tokenVerifier = tokenVerifier;
        this.userService = userService;
    }

    @GetMapping(TOKEN_REFRESH_ENTRY_POINT)
    public JwtToken refreshToken(HttpServletRequest request) {
        String tokenPayload = tokenExtractor.extract(request.getHeader(jwtSettings.getRequestHeader()));

        RawJwtToken rawJwtToken = new RawJwtToken(tokenPayload);
        RefreshToken refreshToken = RefreshToken.create(rawJwtToken, jwtSettings.getTokenSigningKey())
                .orElseThrow(() -> new JwtInvalidTokenException(rawJwtToken, ErrorMessage.REFRESH_TOKEN_INVALID, null));

        String jti = refreshToken.getJti();
        if (!tokenVerifier.verify(jti)) {
            throw new JwtInvalidTokenException(rawJwtToken, ErrorMessage.REFRESH_TOKEN_INVALID, null);
        }

        String username = refreshToken.getSubject();

        AppUser appUser = userService.getByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(ErrorMessage.USERNAME_NOT_FOUND + username));

        if (appUser.getRoles() == null) throw new InsufficientAuthenticationException(ErrorMessage.USER_HAS_NO_ROLES);
        List<GrantedAuthority> authorities = appUser.getRoles().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getRole().authority()))
                .collect(Collectors.toList());

        UserDetails authenticatedUser = new User(username, null, authorities);

        return tokenFactory.createJwtAccessToken(authenticatedUser);
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

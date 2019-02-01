package com.higgsup.security.config.provider;

import com.higgsup.common.exceptions.ErrorMessage;
import com.higgsup.security.entity.AppUser;
import com.higgsup.security.user.IUserService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.List;
import java.util.stream.Collectors;

/**
 * <b>File Created</b>: Feb 01, 2019
 *
 * <b>Author</b>: hungnh
 */
@Component
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {
    private final IUserService userService;
    private final PasswordEncoder passwordEncoder;

    public UsernamePasswordAuthenticationProvider(IUserService userService,
                                                  PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.notNull(authentication, ErrorMessage.NO_AUTHENTICATION_DATA_PROVIDED);

        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        AppUser appUser = userService.getByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(ErrorMessage.USERNAME_NOT_FOUND + username));

        if (!passwordEncoder.matches(password, appUser.getPassword())) {
            throw new BadCredentialsException(ErrorMessage.INVALID_USER_NAME_OR_PASSWORD);
        }

        if (appUser.getRoles() == null) throw new InsufficientAuthenticationException(ErrorMessage.USER_HAS_NO_ROLES);

        List<GrantedAuthority> authorities = appUser.getRoles().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getRole().authority()))
                .collect(Collectors.toList());

        UserDetails authenticatedUser = new User(username, password, authorities);

        return new UsernamePasswordAuthenticationToken(authenticatedUser, null, authenticatedUser.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

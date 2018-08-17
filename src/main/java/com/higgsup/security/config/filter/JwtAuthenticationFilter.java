package com.higgsup.security.config.filter;

import com.higgsup.security.jwt.JwtSettings;
import com.higgsup.security.jwt.extractor.TokenExtractor;
import com.higgsup.security.jwt.token.JwtAuthenticationToken;
import com.higgsup.security.jwt.token.RawJwtToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final AuthenticationSuccessHandler authSuccessHandler;
    private final AuthenticationFailureHandler authFailureHandler;
    private final TokenExtractor tokenExtractor;
    private final JwtSettings jwtSettings;

    public JwtAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher,
                                   AuthenticationSuccessHandler authSuccessHandler,
                                   AuthenticationFailureHandler authFailureHandler,
                                   TokenExtractor tokenExtractor,
                                   JwtSettings jwtSettings) {
        super(requiresAuthenticationRequestMatcher);
        this.authSuccessHandler = authSuccessHandler;
        this.authFailureHandler = authFailureHandler;
        this.tokenExtractor = tokenExtractor;
        this.jwtSettings = jwtSettings;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        String tokenPayload = request.getHeader(jwtSettings.getRequestHeader());
        RawJwtToken rawAccessToken = new RawJwtToken(tokenExtractor.extract(tokenPayload));
        Authentication tokenAuthRequest = new JwtAuthenticationToken(rawAccessToken);
        return getAuthenticationManager().authenticate(tokenAuthRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult)
            throws IOException, ServletException {
        authSuccessHandler.onAuthenticationSuccess(request, response, authResult);
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException failed)
            throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        authFailureHandler.onAuthenticationFailure(request, response, failed);
    }
}

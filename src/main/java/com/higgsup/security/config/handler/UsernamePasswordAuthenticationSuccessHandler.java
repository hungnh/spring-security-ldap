package com.higgsup.security.config.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.higgsup.security.model.LoginResponse;
import com.higgsup.security.jwt.token.JwtToken;
import com.higgsup.security.jwt.token.JwtTokenFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class UsernamePasswordAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;
    private final JwtTokenFactory tokenFactory;

    @Autowired
    public UsernamePasswordAuthenticationSuccessHandler(ObjectMapper objectMapper, JwtTokenFactory tokenFactory) {
        this.objectMapper = objectMapper;
        this.tokenFactory = tokenFactory;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        UserDetails user = (UserDetails) authentication.getPrincipal();

        JwtToken accessToken = tokenFactory.createJwtAccessToken(user);
        JwtToken refreshToken = tokenFactory.createJwtRefreshToken(user);

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setToken(accessToken.getToken());
        loginResponse.setRefreshToken(refreshToken.getToken());

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), loginResponse);
    }
}

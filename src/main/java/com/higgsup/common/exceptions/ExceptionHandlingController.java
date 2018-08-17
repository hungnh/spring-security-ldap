package com.higgsup.common.exceptions;

import com.higgsup.security.exceptions.JwtExpiredTokenException;
import com.higgsup.security.exceptions.JwtInvalidTokenException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@ControllerAdvice(annotations = {RestController.class})
@ResponseBody
public class ExceptionHandlingController {

    @ExceptionHandler({JwtInvalidTokenException.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse jwtInvalidTokenExceptionHandler(Exception ex,
                                                         HttpServletRequest request,
                                                         HttpServletResponse response) {
        return ErrorResponse.of(ex.getMessage(), ErrorCode.ACCESS_TOKEN_INVALID, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler({JwtExpiredTokenException.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse jwtExpiredTokenExceptionHandler(Exception ex,
                                                         HttpServletRequest request,
                                                         HttpServletResponse response) {
        return ErrorResponse.of(ex.getMessage(), ErrorCode.ACCESS_TOKEN_EXPIRED, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler({BadCredentialsException.class, UsernameNotFoundException.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse badCredentialsExceptionHandler(Exception ex,
                                                        HttpServletRequest request,
                                                        HttpServletResponse response) {
        return ErrorResponse.of(ex.getMessage(), ErrorCode.BAD_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }


    @ExceptionHandler({AuthenticationServiceException.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse authenticationServiceExceptionHandler(Exception ex,
                                                               HttpServletRequest request,
                                                               HttpServletResponse response) {
        return ErrorResponse.of(ex.getMessage(), ErrorCode.AUTHENTICATION_FAILED, HttpStatus.UNAUTHORIZED);
    }


    @ExceptionHandler({AccessDeniedException.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse accessDeniedExceptionHandler(Exception ex,
                                                      HttpServletRequest request,
                                                      HttpServletResponse response) {
        return ErrorResponse.of(ex.getMessage(), ErrorCode.AUTHORIZATION_FAILED, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler({Exception.class})
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorResponse anyException(Exception ex,
                                      HttpServletRequest request,
                                      HttpServletResponse response) {
        return ErrorResponse.of(ex.getMessage(), ErrorCode.INTERNAL_SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

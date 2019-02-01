package com.higgsup.security.jwt.extractor;

import com.higgsup.common.exceptions.ErrorMessage;
import com.higgsup.security.constants.SecurityConstants;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class JwtHeaderTokenExtractor implements TokenExtractor {

    @Override
    public String extract(String header) {
        if (StringUtils.isEmpty(header)) {
            throw new AuthenticationServiceException(ErrorMessage.MISSING_AUTHORIZATION_HEADER);
        }

        if (!header.contains(SecurityConstants.AUTHORIZATION_HEADER_PREFIX)) {
            throw new AuthenticationServiceException(ErrorMessage.AUTHORIZATION_HEADER_INVALID);
        }

        return header.substring(SecurityConstants.AUTHORIZATION_HEADER_PREFIX.length());
    }
}

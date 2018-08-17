package com.higgsup.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "com.higgsup.security.jwt")
public class JwtSettings {
    private String requestHeader;
    private Integer tokenExpTime;
    private Integer refreshTokenExpTime;
    private String tokenSigningKey;

    public String getRequestHeader() {
        return requestHeader;
    }

    public void setRequestHeader(String requestHeader) {
        this.requestHeader = requestHeader;
    }

    public Integer getTokenExpTime() {
        return tokenExpTime;
    }

    public void setTokenExpTime(Integer tokenExpTime) {
        this.tokenExpTime = tokenExpTime;
    }

    public Integer getRefreshTokenExpTime() {
        return refreshTokenExpTime;
    }

    public void setRefreshTokenExpTime(Integer refreshTokenExpTime) {
        this.refreshTokenExpTime = refreshTokenExpTime;
    }

    public String getTokenSigningKey() {
        return tokenSigningKey;
    }

    public void setTokenSigningKey(String tokenSigningKey) {
        this.tokenSigningKey = tokenSigningKey;
    }
}

package com.higgsup.security.jwt.extractor;

public interface TokenExtractor {
    String extract(String payload);
}

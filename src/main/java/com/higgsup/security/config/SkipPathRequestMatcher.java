package com.higgsup.security.config;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

public class SkipPathRequestMatcher implements RequestMatcher {
    private OrRequestMatcher skippingMatcher;
    private RequestMatcher processingMatcher;

    public SkipPathRequestMatcher(List<String> pathsToSkip, String pathToProcess) {
        skippingMatcher = new OrRequestMatcher(pathsToSkip.stream().map(AntPathRequestMatcher::new).collect(Collectors.toList()));
        processingMatcher = new AntPathRequestMatcher(pathToProcess);
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return !skippingMatcher.matches(request) && processingMatcher.matches(request);
    }
}

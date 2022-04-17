package com.ethen.usecase.web.filter;

import org.apache.commons.lang3.StringUtils;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 给指定路径的请求添加 content-length
 *
 * @author ethen
 * @since 2022/04/15
 */
public class ContentLengthFilter extends OncePerRequestFilter {
    private final List<String> patternList = new ArrayList<>();

    public ContentLengthFilter(String requestList) {
        if (StringUtils.isNoneBlank(requestList)) {
            patternList.addAll(Arrays.asList(requestList.split(";")));
        }
    }

    /**
     * Same contract as for {@code doFilter}, but guaranteed to be
     * just invoked once per request within a single request thread.
     * See {@link #shouldNotFilterAsyncDispatch()} for details.
     * <p>Provides HttpServletRequest and HttpServletResponse arguments instead of the
     * default ServletRequest and ServletResponse ones.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        ContentCachingResponseWrapper cachingResponseWrapper;
        String uri = request.getRequestURI();
        AntPathMatcher antPathMatcher = new AntPathMatcher();

        // 请求不在列表范围内
        if (patternList.stream().noneMatch(pt -> antPathMatcher.match(pt, uri))) {
            filterChain.doFilter(request, response);
            return;
        }

        // 列表范围设置 content-length
        if (response instanceof ContentCachingResponseWrapper) {
            cachingResponseWrapper = new ContentCachingResponseWrapper(response);
        } else {
            cachingResponseWrapper = new ContentCachingResponseWrapper(response);
        }
        filterChain.doFilter(request, cachingResponseWrapper);
        cachingResponseWrapper.copyBodyToResponse();
    }
}

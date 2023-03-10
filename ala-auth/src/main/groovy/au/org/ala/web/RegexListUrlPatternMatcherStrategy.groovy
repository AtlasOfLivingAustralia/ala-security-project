package au.org.ala.web

import org.jasig.cas.client.authentication.UrlPatternMatcherStrategy

import java.util.regex.Pattern

class RegexListUrlPatternMatcherStrategy implements UrlPatternMatcherStrategy {

    List<Pattern> patterns = []

    @Override
    boolean matches(String url) {
        return patterns.any { pattern -> pattern.matcher(url).matches() }
    }

    @Override
    void setPattern(String pattern) {
        this.patterns = pattern.split(',').collect { Pattern.compile(it, Pattern.CASE_INSENSITIVE)}
    }
}

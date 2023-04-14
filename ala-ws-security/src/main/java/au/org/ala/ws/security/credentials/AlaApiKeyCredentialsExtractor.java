package au.org.ala.ws.security.credentials;

import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.extractor.HeaderExtractor;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class AlaApiKeyCredentialsExtractor extends HeaderExtractor {
    public AlaApiKeyCredentialsExtractor() {
        setHeaderName("apiKey");
        setPrefixHeader("");
    }

    @Override
    public void setHeaderName(String headerName) {
        super.setHeaderName(headerName);
    }

    public void setAlternativeHeaderNames(List<String> alternativeHeaderNames) {

        alternativeHeaderExtractors = alternativeHeaderNames.stream().map( alternativeHeaderName -> {
            AlaApiKeyCredentialsExtractor alternativeHeaderExtractor = new AlaApiKeyCredentialsExtractor();
            alternativeHeaderExtractor.setHeaderName(alternativeHeaderName);
            return alternativeHeaderExtractor;
        }).collect(Collectors.toList());
    }

    @Override
    public Optional<Credentials> extract(final WebContext context, final SessionStore sessionStore) {

        final Optional<Credentials> credentials = super.extract(context, sessionStore);

        if (credentials.isPresent()) {
            return credentials;
        }

        return alternativeHeaderExtractors.stream()
                .map(alternativeHeaderExtractor -> alternativeHeaderExtractor.extract(context, sessionStore))
                .flatMap(Optional::stream)
                .findFirst();
    }

    public List<AlaApiKeyCredentialsExtractor> getAlternativeHeaderExtractors() {
        return alternativeHeaderExtractors;
    }

    public void setAlternativeHeaderExtractors(List<AlaApiKeyCredentialsExtractor> alternativeHeaderExtractors) {
        this.alternativeHeaderExtractors = alternativeHeaderExtractors;
    }

    private List<AlaApiKeyCredentialsExtractor> alternativeHeaderExtractors = new ArrayList<AlaApiKeyCredentialsExtractor>();
}

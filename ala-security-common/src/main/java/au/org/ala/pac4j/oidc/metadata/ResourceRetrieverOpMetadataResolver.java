package au.org.ala.pac4j.oidc.metadata;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.exceptions.OidcException;
import org.pac4j.oidc.metadata.OidcOpMetadataResolver;

import java.io.IOException;

/**
 * Use the pre-configured resource resolver to resolve the OIDC Provider Metadata.
 */
public class ResourceRetrieverOpMetadataResolver extends OidcOpMetadataResolver {

    public ResourceRetrieverOpMetadataResolver(OidcConfiguration configuration) {
        super(configuration);
    }

    @Override
    protected OIDCProviderMetadata retrieveMetadata() {
        try {
            if (resource.getURL().getProtocol().equals("classpath")) {
                return super.retrieveMetadata(); // use the default resolver for classpath URLs
            }
            OIDCProviderMetadata metadata;
            String content = configuration.findResourceRetriever().retrieveResource(resource.getURL()).getContent();
            metadata = OIDCProviderMetadata.parse(content);

            return metadata;
        } catch (ParseException | IOException e) {
            throw new OidcException("Error getting OP metadata", e);
        }
    }
}

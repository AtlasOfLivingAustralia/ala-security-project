package au.org.ala.ws.security;

import com.nimbusds.jose.JWSAlgorithm;
import org.pac4j.jwt.config.signature.ECSignatureConfiguration;
import org.pac4j.jwt.config.signature.RSASignatureConfiguration;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.config.signature.SignatureConfiguration;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


public class SignatureConfigurationProperties {

    String type;
    String publicKey;
    String privateKey;
    String secret;
    String jwsAlgorithm;


    public SignatureConfiguration toSignatureConfiguration() {
        try {
            if ("rsa".equals(type)) {
                byte[] decoded = java.util.Base64.getDecoder().decode(publicKey);
                X509EncodedKeySpec spec =
                        new X509EncodedKeySpec(decoded);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(spec);
                return new RSASignatureConfiguration(new KeyPair(publicKey, null), JWSAlgorithm.parse(jwsAlgorithm));
            } else if ("secret".equals(type)) {
                return new SecretSignatureConfiguration(secret, JWSAlgorithm.parse(jwsAlgorithm));
            } else if ("ec".equals(type)) {
                byte[] decoded = java.util.Base64.getDecoder().decode(publicKey);
                X509EncodedKeySpec spec =
                        new X509EncodedKeySpec(decoded);
                KeyFactory kf = KeyFactory.getInstance("EC");
                ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(spec);

                return new ECSignatureConfiguration(new KeyPair(publicKey, null), JWSAlgorithm.parse(jwsAlgorithm));
            } else {
                throw new IllegalArgumentException("Unknown key type: " + type);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("Error creating signature configuration", e);
        }
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getJwsAlgorithm() {
        return jwsAlgorithm;
    }

    public void setJwsAlgorithm(String jwsAlgorithm) {
        this.jwsAlgorithm = jwsAlgorithm;
    }
}

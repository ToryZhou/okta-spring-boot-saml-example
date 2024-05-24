package com.example.demo;

import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.util.Assert;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

@Configuration
public class Saml2ConfigOfficial {

    private RelyingPartyRegistration.Builder addRelyingPartyDetails(RelyingPartyRegistration.Builder builder) {
        Saml2RelyingPartyProperties.Registration.Signing.Credential credential = new Saml2RelyingPartyProperties.Registration.Signing.Credential();
        credential.setCertificateLocation(new ClassPathResource("local.crt"));
        credential.setPrivateKeyLocation(new ClassPathResource("local.key"));
        Saml2X509Credential signingCredential = asSigningCredential(credential);
        builder.signingX509Credentials(c -> c.add(signingCredential));
        return builder;
    }

    private Saml2X509Credential asSigningCredential(Saml2RelyingPartyProperties.Registration.Signing.Credential properties) {
        RSAPrivateKey privateKey = readPrivateKey(properties.getPrivateKeyLocation());
        X509Certificate certificate = readCertificate(properties.getCertificateLocation());
        return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
    }

    private RSAPrivateKey readPrivateKey(Resource location) {
        Assert.state(location != null, "No private key location specified");
        Assert.state(location.exists(), () -> "Private key location '" + location + "' does not exist");
        try (InputStream inputStream = location.getInputStream()) {
            return RsaKeyConverters.pkcs8().convert(inputStream);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    private X509Certificate readCertificate(Resource location) {
        Assert.state(location != null, "No certificate location specified");
        Assert.state(location.exists(), () -> "Certificate  location '" + location + "' does not exist");
        try (InputStream inputStream = location.getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() {
        RelyingPartyRegistration okta = addRelyingPartyDetails(
                RelyingPartyRegistrations
                        .fromMetadataLocation("https://dev-42439037.okta.com/app/exkh80bqywy7ffjqV5d7/sso/saml/metadata")
                        .registrationId("okta")).build();

        RelyingPartyRegistration azure = addRelyingPartyDetails(
                RelyingPartyRegistrations
                        .fromMetadataLocation("https://dev-42439037.okta.com/app/exkh80bqywy7ffjqV5d7/sso/saml/metadata")
                        .registrationId("azure")).build();

        return new InMemoryRelyingPartyRegistrationRepository(okta, azure);
    }

}

package com.example.demo;

import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

//@Configuration
public class Saml2ConfigSpringBoot {

//    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {

        Saml2RelyingPartyProperties properties = new Saml2RelyingPartyProperties();
        Saml2RelyingPartyProperties.Registration registration = new Saml2RelyingPartyProperties.Registration();
//        registration.setEntityId("{baseUrl}/saml2/service-provider-metadata/{registrationId}");
        registration.setEntityId("http://www.okta.com/exkh80bqywy7ffjqV5d7");
        Saml2RelyingPartyProperties.Registration.Signing signing = registration.getSigning();
        List<Saml2RelyingPartyProperties.Registration.Signing.Credential> credentials = signing.getCredentials();
        Saml2RelyingPartyProperties.Registration.Signing.Credential credential = new Saml2RelyingPartyProperties.Registration.Signing.Credential();
        credential.setCertificateLocation(new ClassPathResource("local.crt"));
        credential.setPrivateKeyLocation(new ClassPathResource("local.key"));
        credentials.add(credential);

        Saml2RelyingPartyProperties.AssertingParty assertingparty = registration.getAssertingparty();
        assertingparty.setMetadataUri("https://dev-42439037.okta.com/app/exkh80bqywy7ffjqV5d7/sso/saml/metadata");

        Saml2RelyingPartyProperties.Singlelogout singlelogout = registration.getSinglelogout();
        singlelogout.setUrl("{baseUrl}/logout/saml2/slo");

        properties.getRegistration().put("okta", registration);
        List<RelyingPartyRegistration> registrations = properties.getRegistration()
                .entrySet()
                .stream()
                .map(this::asRegistration)
                .toList();

        return new InMemoryRelyingPartyRegistrationRepository(registrations);
    }

    private RelyingPartyRegistration asRegistration(Map.Entry<String, Saml2RelyingPartyProperties.Registration> entry) {
        return asRegistration(entry.getKey(), entry.getValue());
    }

    private RelyingPartyRegistration asRegistration(String id, Saml2RelyingPartyProperties.Registration properties) {
        boolean usingMetadata = StringUtils.hasText(properties.getAssertingparty().getMetadataUri());
        RelyingPartyRegistration.Builder builder = (usingMetadata)
                ? RelyingPartyRegistrations.fromMetadataLocation(properties.getAssertingparty().getMetadataUri())
                .registrationId(id)
                : RelyingPartyRegistration.withRegistrationId(id);
        builder.assertionConsumerServiceLocation(properties.getAcs().getLocation());
        builder.assertionConsumerServiceBinding(properties.getAcs().getBinding());
        builder.assertingPartyDetails(mapAssertingParty(properties.getAssertingparty(), usingMetadata));
        builder.signingX509Credentials((credentials) -> properties.getSigning()
                .getCredentials()
                .stream()
                .map(this::asSigningCredential)
                .forEach(credentials::add));
        builder.decryptionX509Credentials((credentials) -> properties.getDecryption()
                .getCredentials()
                .stream()
                .map(this::asDecryptionCredential)
                .forEach(credentials::add));
        builder.assertingPartyDetails(
                (details) -> details.verificationX509Credentials((credentials) -> properties.getAssertingparty()
                        .getVerification()
                        .getCredentials()
                        .stream()
                        .map(this::asVerificationCredential)
                        .forEach(credentials::add)));
        builder.singleLogoutServiceLocation(properties.getSinglelogout().getUrl());
        builder.singleLogoutServiceResponseLocation(properties.getSinglelogout().getResponseUrl());
        builder.singleLogoutServiceBinding(properties.getSinglelogout().getBinding());
        builder.entityId(properties.getEntityId());
        RelyingPartyRegistration registration = builder.build();
        boolean signRequest = registration.getAssertingPartyDetails().getWantAuthnRequestsSigned();
        validateSigningCredentials(properties, signRequest);
        return registration;
    }

    private Consumer<RelyingPartyRegistration.AssertingPartyDetails.Builder> mapAssertingParty(Saml2RelyingPartyProperties.AssertingParty assertingParty,
                                                                                               boolean usingMetadata) {
        return (details) -> {
            PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
            map.from(assertingParty::getEntityId).to(details::entityId);
            map.from(assertingParty.getSinglesignon()::getBinding).to(details::singleSignOnServiceBinding);
            map.from(assertingParty.getSinglesignon()::getUrl).to(details::singleSignOnServiceLocation);
            map.from(assertingParty.getSinglesignon()::isSignRequest)
                    .when((signRequest) -> !usingMetadata)
                    .to(details::wantAuthnRequestsSigned);
            map.from(assertingParty.getSinglelogout()::getUrl).to(details::singleLogoutServiceLocation);
            map.from(assertingParty.getSinglelogout()::getResponseUrl).to(details::singleLogoutServiceResponseLocation);
            map.from(assertingParty.getSinglelogout()::getBinding).to(details::singleLogoutServiceBinding);
        };
    }

    private void validateSigningCredentials(Saml2RelyingPartyProperties.Registration properties, boolean signRequest) {
        if (signRequest) {
            Assert.state(!properties.getSigning().getCredentials().isEmpty(),
                    "Signing credentials must not be empty when authentication requests require signing.");
        }
    }

    private Saml2X509Credential asSigningCredential(Saml2RelyingPartyProperties.Registration.Signing.Credential properties) {
        RSAPrivateKey privateKey = readPrivateKey(properties.getPrivateKeyLocation());
        X509Certificate certificate = readCertificate(properties.getCertificateLocation());
        return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
    }

    private Saml2X509Credential asDecryptionCredential(Saml2RelyingPartyProperties.Decryption.Credential properties) {
        RSAPrivateKey privateKey = readPrivateKey(properties.getPrivateKeyLocation());
        X509Certificate certificate = readCertificate(properties.getCertificateLocation());
        return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
    }

    private Saml2X509Credential asVerificationCredential(Saml2RelyingPartyProperties.AssertingParty.Verification.Credential properties) {
        X509Certificate certificate = readCertificate(properties.getCertificateLocation());
        return new Saml2X509Credential(certificate, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION,
                Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
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
}

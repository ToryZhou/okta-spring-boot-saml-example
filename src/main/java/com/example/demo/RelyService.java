package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.stereotype.Service;

@Service
public class RelyService {

//    @Autowired
//    private InMemoryRelyingPartyRegistrationRepository inMemoryRelyingPartyRegistrationRepository;

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    public void get() {
        System.out.println("get");
        RelyingPartyRegistration okta = relyingPartyRegistrationRepository.findByRegistrationId("okta");
        RelyingPartyRegistration okta2 = relyingPartyRegistrationRepository.findByRegistrationId("idpEntityId");
        RelyingPartyRegistration okta3 = relyingPartyRegistrationRepository.findByRegistrationId("http://www.okta.com/exkh80bqywy7ffjqV5d7");

//        System.out.println(okta.getAssertingPartyDetails().getEntityId());
//        System.out.println(okta2.getAssertingPartyDetails().getEntityId());
        System.out.println(okta3.getAssertingPartyDetails().getEntityId());
//        Iterator<RelyingPartyRegistration> iterator = inMemoryRelyingPartyRegistrationRepository.iterator();
//        while (iterator.hasNext()) {
//            RelyingPartyRegistration relyingPartyRegistration = iterator.next();
//            System.out.println(relyingPartyRegistration.getAssertingPartyDetails().getEntityId());
//        }

    }

}

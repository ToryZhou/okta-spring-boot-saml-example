package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class Saml2DynamicIdpConfig {

//    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        // 创建一个内存存储的RelyingPartyRegistrationRepository
//        InMemoryRelyingPartyRegistrationRepository repository = new InMemoryRelyingPartyRegistrationRepository();

        // 动态添加IdP配置
        Map<String, RelyingPartyRegistration> registrations = new HashMap<>();

//        List<RelyingPartyRegistration> registrations = properties.getRegistration()
//                .entrySet()
//                .stream()
//                .map(this::asRegistration)
//                .toList();

        // 假设有一个方法用于获取IdP的配置信息
        RelyingPartyRegistration idpRegistration = getIdpConfiguration("idpEntityId");
//        registrations.put("idpEntityId", idpRegistration);

        InMemoryRelyingPartyRegistrationRepository repository = new InMemoryRelyingPartyRegistrationRepository(idpRegistration);

        // 将配置信息添加到repository中
//        repository.setRegistrations(registrations);

        return repository;
    }



    //
    private RelyingPartyRegistration getIdpConfiguration(String entityId) {
        // 这里应该是获取IdP配置信息的逻辑
        // 例如，从数据库或配置文件中读取
        // 以下是一个示例配置
        return RelyingPartyRegistrations
                .fromMetadataLocation("https://dev-42439037.okta.com/app/exkh80bqywy7ffjqV5d7/sso/saml/metadata")
                .entityId(entityId)
                // 其他配置...
                .build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //        http.csrf().disable().authorizeHttpRequests().anyRequest().permitAll();
//        Saml2LoginConfigurer<HttpSecurity> saml2Login = http.getConfigurer(Saml2LoginConfigurer.class);
//        // 配置SAML2登录
//        saml2Login.relyingPartyRegistrationRepository(relyingPartyRegistrationRepository());

//        http.csrf().disable().authorizeHttpRequests().requestMatchers("/test/value").permitAll().anyRequest().authenticated();
//
//
//// 其他安全配置...
//        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
//        authenticationProvider.setResponseAuthenticationConverter(groupsConverter());
//
//        http.authorizeHttpRequests(authorize -> authorize
//                        .anyRequest().authenticated())
//                .saml2Login(saml2 -> saml2
//                        .authenticationManager(new ProviderManager(authenticationProvider)))
//                .saml2Logout(withDefaults());

        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(groupsConverter()); // 确保这是有效的转换器
//        http.csrf().disable().authorizeHttpRequests().anyRequest().permitAll();
//        http
//                .csrf().disable() // 如果您不需要CSRF保护，可以禁用它
//                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/test/value", "/test/zz", "/login/saml2/sso/okta", "/saml2/service-provider-metadata/okta").permitAll() // 只有 "/test/value" 请求允许所有人访问
//                        .anyRequest().authenticated() // 其他所有请求需要身份验证
//                )
//                .saml2Login(saml2 -> saml2
//                        .authenticationManager(new ProviderManager(authenticationProvider)) // 设置认证管理器
//                )
//                .saml2Logout(withDefaults()); // 配置SAML 2.0 Logout

        http
                .csrf().disable() // 如果您不需要CSRF保护，可以禁用它
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/saml2/authenticate/okta", "/saml2/authenticate/azure")
                        .authenticated() .anyRequest().permitAll()
                )
                .saml2Login(saml2 -> saml2
                        .authenticationManager(new ProviderManager(authenticationProvider)) // 设置认证管理器
                )
                .saml2Logout(withDefaults()); // 配置SAML 2.0 Logout

//        http.csrf().disable().authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers( "/saml2/service-provider-metadata/okta", "/saml2/service-provider-metadata/azure")).saml2Login(saml2 -> saml2
//                        .authenticationManager(new ProviderManager(authenticationProvider)));


//        http
//                // 禁用CSRF保护，因为SAML通常与CSRF保护不兼容
//                .csrf().disable()
//                // 配置授权请求
//                .authorizeHttpRequests(authorize -> authorize
//                        // 允许所有人访问所有路径
//                        .anyRequest().permitAll()
//                        // 只有以下两个路径需要身份验证
//                        .requestMatchers("/saml2/service-provider-metadata/okta", "/saml2/service-provider-metadata/azure")
//                        .authenticated()
//                )
//                // 配置SAML2登录
//                .saml2Login(saml2 -> saml2
//                                .authenticationManager(new ProviderManager(authenticationProvider))
//                        // 其他SAML2配置...
//                );

        return http.build();
    }



    private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> groupsConverter() {

        Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> delegate =
                OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter();

        return (responseToken) -> {
            Saml2Authentication authentication = delegate.convert(responseToken);
            Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
            List<String> groups = principal.getAttribute("groups");
            Set<GrantedAuthority> authorities = new HashSet<>();
            if (groups != null) {
                groups.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
            } else {
                authorities.addAll(authentication.getAuthorities());
            }
            return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
        };
    }
}
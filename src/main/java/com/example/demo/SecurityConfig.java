//package com.example.demo;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.web.DefaultSecurityFilterChain;
//import org.springframework.security.web.SecurityFilterChain;
//
//@EnableWebSecurity
//public class SecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>{
//
////    @Override
////    public void configure(HttpSecurity http) throws Exception {
////        http
////                // 禁用CSRF保护
////                .csrf().disable()
////                // 允许所有请求
////                .authorizeHttpRequests()
////                .anyRequest().permitAll();
////    }
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.csrf().disable().authorizeHttpRequests().anyRequest().permitAll();
//        return http.build();
//    }
//}
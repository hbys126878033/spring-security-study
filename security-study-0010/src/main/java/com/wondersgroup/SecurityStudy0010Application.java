package com.wondersgroup;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecurityStudy0010Application {

    public static void main(String[] args) {
        SpringApplication.run(SecurityStudy0010Application.class, args);
    }



    @Bean
    public CommandLineRunner commandLineRunner(ApplicationContext context){

        /**
         *
         * id = org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration , class = class org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration
         * id = spring.security.oauth2.resourceserver-org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties , class = class org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties
         * id = org.springframework.boot.autoconfigure.security.servlet.SpringBootWebSecurityConfiguration$DefaultConfigurerAdapter , class = class org.springframework.boot.autoconfigure.security.servlet.SpringBootWebSecurityConfiguration$DefaultConfigurerAdapter

         * id = org.springframework.boot.autoconfigure.security.servlet.SpringBootWebSecurityConfiguration , class = class org.springframework.boot.autoconfigure.security.servlet.SpringBootWebSecurityConfiguration
         * id = org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration , class = class org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration

         * id = objectPostProcessor , class = class org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessor
         * id = org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration , class = class org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
         * id = authenticationManagerBuilder , class = class org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration$DefaultPasswordEncoderAuthenticationManagerBuilder
         * id = enableGlobalAuthenticationAutowiredConfigurer , class = class org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration$EnableGlobalAuthenticationAutowiredConfigurer
         * id = initializeUserDetailsBeanManagerConfigurer , class = class org.springframework.security.config.annotation.authentication.configuration.InitializeUserDetailsBeanManagerConfigurer
         * id = initializeAuthenticationProviderBeanManagerConfigurer , class = class org.springframework.security.config.annotation.authentication.configuration.InitializeAuthenticationProviderBeanManagerConfigurer

         * id = org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration , class = class org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration

         * id = delegatingApplicationListener , class = class org.springframework.security.context.DelegatingApplicationListener
         * id = webSecurityExpressionHandler , class = class org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler

         * id = springSecurityFilterChain , class = class org.springframework.security.web.FilterChainProxy

         * id = privilegeEvaluator , class = class org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator
         * id = conversionServicePostProcessor , class = class org.springframework.security.config.crypto.RsaKeyConversionServicePostProcessor
         * id = autowiredWebSecurityConfigurersIgnoreParents , class = class org.springframework.security.config.annotation.web.configuration.AutowiredWebSecurityConfigurersIgnoreParents
         * id = org.springframework.security.config.annotation.web.configuration.WebMvcSecurityConfiguration , class = class org.springframework.security.config.annotation.web.configuration.WebMvcSecurityConfiguration
         * id = requestDataValueProcessor , class = class org.springframework.security.web.servlet.support.csrf.CsrfRequestDataValueProcessor
         * id = org.springframework.boot.autoconfigure.security.servlet.WebSecurityEnablerConfiguration , class = class org.springframework.boot.autoconfigure.security.servlet.WebSecurityEnablerConfiguration
         * id = org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration , class = class org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration
         * id = authenticationEventPublisher , class = class org.springframework.security.authentication.DefaultAuthenticationEventPublisher
         * id = spring.security-org.springframework.boot.autoconfigure.security.SecurityProperties , class = class org.springframework.boot.autoconfigure.security.SecurityProperties
         * id = org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration , class = class org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration
         * id = securityFilterChainRegistration , class = class org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean
         * id = org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration , class = class org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration
         * id = inMemoryUserDetailsManager , class = class org.springframework.security.provisioning.InMemoryUserDetailsManager
         */



        return new CommandLineRunner() {

            @Override
            public void run(String... args) throws Exception {
                String[] names = context.getBeanDefinitionNames();
                for (String name : names) {
                   // System.out.println("id = "+name + " , class = "+context.getBean(name).getClass());
                }
            }
        };

    }
}

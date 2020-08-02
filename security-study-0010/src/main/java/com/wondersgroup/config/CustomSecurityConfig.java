package com.wondersgroup.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wondersgroup.custom.CustomUserDetailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author chenlin
 * @create 2020-07-30 9:51
 * @description: SpringSecurity
 * @version：1.0
 **/
@Configuration
@EnableWebSecurity
@Slf4j
public class CustomSecurityConfig  extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    @Bean
    public UserDetailsService customUserDetailService(){
        return new CustomUserDetailService();
    }

    @Bean
    public PasswordEncoder BCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }




    /**认证逻辑*/
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /**
         * AuthenticationManagerBuilder用来配置全局的认证相关的信息，
         * 其实就是AuthenticationProvider和UserDetailsService，
         * 前者是认证服务提供者，后者是认证用户（及其权限）。
         * */


         auth.inMemoryAuthentication().passwordEncoder(BCryptPasswordEncoder()).withUser("admin").password(BCryptPasswordEncoder().encode("admin")).roles("ADMIN");

        //auth.userDetailsService(customUserDetailService());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        /**
         * 可以设置全局的忽略规则的配置，比如静态文件，注册页面，登录页面等等，
         * 全局HttpFirewall配置、是否debug配置、全局SecurityFilterChain配置、
         * privilegeEvaluator、expressionHandler、securityInterceptor
         */
        web.ignoring().antMatchers(
                "/layui/**",
                "/favicon.ico");

    }

    /**授权逻辑*/
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /**
         * HttpSecurity 具体的权限控制规则配置。一个这个配置相当于xml配置中的一个标签。
         * 各种具体的认证机制的相关配置，OpenIDLoginConfigurer、AnonymousConfigurer、FormLoginConfigurer、HttpBasicConfigurer
         * LogoutConfigurer
         * RequestMatcherConfigurer：spring mvc style、ant style、regex style
         * HeadersConfigurer：
         * CorsConfigurer、CsrfConfigurer
         * SessionManagementConfigurer：
         * PortMapperConfigurer：
         * JeeConfigurer：
         * X509Configurer：
         * RememberMeConfigurer：
         * ExpressionUrlAuthorizationConfigurer：
         * RequestCacheConfigurer：
         * ExceptionHandlingConfigurer：
         * SecurityContextConfigurer：
         * ServletApiConfigurer：
         * ChannelSecurityConfigurer：
         *
         * */

        http.csrf().disable()
                .authorizeRequests().antMatchers("/","/index","/error").permitAll()
                .anyRequest().authenticated()
                .and()
                /** 设置未授权请求跳转到登录页面：开启表单登 录功能 */
                .formLogin()
                /**指定登录页面，并且允许不授权访问 */
                .loginPage("/index")
                .permitAll()
                /** 指定提交表单的地址,SpringSecurity 会处理登录的逻辑，不需要自己定义controller*/
                .loginProcessingUrl("/login")
                //.permitAll()
                /**定制登录的参数名称*/
                .usernameParameter("loginName")
                .passwordParameter("password")
                /**指定登录失败时跳转的URL*/
                //.failureForwardUrl("/index")

                /**定制登录失败的逻辑，可以分别对表单和AJAX请求进行定制处理*/
                .failureHandler(customAuthenticationFailureHandler)
                /*.failureHandler(new AuthenticationFailureHandler(){
                        @Override
                        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                            log.info("================账号密码不对=======================");
                            request.setAttribute("message","账号密码不匹配");
                           // request.getRequestDispatcher("/index").forward(request,response);
                            response.sendRedirect("/index?message=1");
                        }
                    }
                )*/
                //.failureUrl("/index")
                /**设置登录成功后默认前往的 URL 地址*/
                .defaultSuccessUrl("/main")
                .and()
                .logout().logoutUrl("/logout").logoutSuccessUrl("/index")
                ;
    }
}

@Component
@Slf4j
class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private static final String AJAX_HEADER_KEY = "X-Requested-With";

    private static final String AJAX_HEADER_VALUE = "XMLHttpRequest";
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        if ( AJAX_HEADER_VALUE.equals(request.getHeader("X-Requested-With"))) {
            Map<String, Object> map = new HashMap<>();
            map.put("code","1002");
            map.put("msg","登录失败");
            map.put("data",exception.getMessage());
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(map));
        }else{
            super.setDefaultFailureUrl("/index?error=true"); // 登录失败，跳转到登录界面
            super.onAuthenticationFailure(request, response, exception);
        }
    }
}

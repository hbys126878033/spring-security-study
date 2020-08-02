package com.wondersgroup.custom;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.List;

/**
 * @author chenlin
 * @create 2020-07-30 17:01
 * @description: TODO
 * @version：1.0
 **/

@Slf4j
public class CustomUserDetailService implements UserDetailsService {


    public CustomUserDetailService(){
        log.info("CustomUserDetailService constructor init ....");
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {


        log.info("username = "+ s);


        if("admin".equals(s)){

            log.info("认证成功");
            List<GrantedAuthority> auth = new ArrayList<>();
            auth.add(new SimpleGrantedAuthority("ADMIN"));
            return new User("admin","admin",auth);
        }else{
            throw new UsernameNotFoundException("not found");
        }
    }
}

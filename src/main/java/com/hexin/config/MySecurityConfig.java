package com.hexin.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private DataSource dataSource;//注入数据源

    @Bean
    public PersistentTokenRepository persistentTokenRepository(){//配置PersistentTokenRepository对象
        JdbcTokenRepositoryImpl jdbcTokenRepository = new
                JdbcTokenRepositoryImpl();
        // 赋值数据源
        jdbcTokenRepository.setDataSource(dataSource);
        // 自动创建表,第一次执行会创建，以后要执行就要删除掉！
        //jdbcTokenRepository.setCreateTableOnStartup(true);//这里我们是自己创建的表就不需要自动创建了
        return jdbcTokenRepository;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(password());
    }

    @Bean
    PasswordEncoder password() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        //配置没有权限时跳转到指定页面（代替默认403页面）
        http.exceptionHandling().accessDeniedPage("/unauth.html");
        //配置用户注销
        http.logout()
            .logoutUrl("/logout")   //用户注销的url
            .logoutSuccessUrl("/test/hello").permitAll();
        http.formLogin()    //自定义自己编写的登录页面
            .loginPage("/login.html")   //登录页面配置
            .loginProcessingUrl("/user/login")  //登录访问URL
            .defaultSuccessUrl("/success.html").permitAll()   //登录成功后的跳转路径
            .and().authorizeRequests()
                .antMatchers("/","/test/hello","/use/login").permitAll()    //设置不需要认证的路径
                //当前登陆的用户只有admins权限才可以访问
                //.antMatchers("/test/index").hasAuthority("admins") //需要带有admins权限
                //需要带有admins或test中任意一个权限
                //.antMatchers("/test/index").hasAnyAuthority("admins,test")
//                //需要用户带有角色role1
//                .antMatchers("/test/index").hasRole("role1")
                //需要用户带有角色role1
//                .antMatchers("/test/index").hasAnyRole("role,admin")
                .antMatchers("/findAll").hasRole("管理员")
                .antMatchers("/find").hasAnyAuthority("menu:system")
                .anyRequest().authenticated()
            .and().rememberMe().tokenRepository(persistentTokenRepository())  //设置自动登录
                  .tokenValiditySeconds(60) //有效时长60s
                  .userDetailsService(userDetailsService)
            .and().csrf().disable();    //关闭csrf防护
    }

}

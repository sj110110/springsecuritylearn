# **Spring Security入门学习**

## **1.Spring Security概述**

## **2.Spring Security入门案例**

1）创建Maven项目

![img](D:\data\youdaoNote\weixinobU7VjoqKsPIOC3vcNuosN7uJCCM\a995b805282e4b8891beee8b79668f7b\clipboard.png)

2）application.properties配置文件

```properties
server.port=8001
```

3）引入POM依赖

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>springsecuritylearn</artifactId>
    <version>1.0-SNAPSHOT</version>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.2.1.RELEASE</version>
        <relativePath/>
    </parent>

    <properties>
        <java.version>1.8</java.version>
    </properties>

    <dependencies>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <!--spring security-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

4）主启动类

```java
package com.hexin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }
}

```

5）业务接口

```java
package com.hexin.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/security")
public class HelloController {

    @GetMapping("hello")
    public String Hello(){
        return "hello security!";
    }
}

```

6)测试

启动服务：

访问：http://localhost:8001/security/hello

可以看到如下界面，这是SpringSecurity内置的登录页面，说明我们集成SpringSecurity成功了。

![img](D:\data\youdaoNote\weixinobU7VjoqKsPIOC3vcNuosN7uJCCM\d1545e67e5114834942ceded48c4fd4b\clipboard.png)

下面我们输入用户名和密码。当我们没有主动配置用户名和密码的时候，默认的用户名为user，密码可以在应用启动日志中查看到。

![img](D:\data\youdaoNote\weixinobU7VjoqKsPIOC3vcNuosN7uJCCM\163a299b37814ed7acbd056d4ae37918\clipboard.png)

当我们输入用户名和密码后，就可以正常登陆了：

![img](D:\data\youdaoNote\weixinobU7VjoqKsPIOC3vcNuosN7uJCCM\5bc15d2c89684af08debdb0e085ec450\clipboard.png)

## 3.Spring Security Web认证授权方案

**Spring Security本质上就是一个过滤器链。**

### 3.1过滤器链

SpringSecurity 本质是一个过滤器链：

从项目启动是可以获取到过滤器链：

```java
org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFil
ter
org.springframework.security.web.context.SecurityContextPersistenceFilter 
org.springframework.security.web.header.HeaderWriterFilter
org.springframework.security.web.csrf.CsrfFilter
org.springframework.security.web.authentication.logout.LogoutFilter 
org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter 
org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter 
org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter
org.springframework.security.web.savedrequest.RequestCacheAwareFilter
org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
org.springframework.security.web.authentication.AnonymousAuthenticationFilter 
org.springframework.security.web.session.SessionManagementFilter 
org.springframework.security.web.access.ExceptionTranslationFilter 
org.springframework.security.web.access.intercept.FilterSecurityInterceptor
```

代码底层流程：重点看三个过滤器：

#### 3.1.1FilterSecurityInterceptor

​	这是一个方法级别的权限过滤器，基本位于过滤器链的最底部。

```java
public void invoke(FilterInvocation fi) throws IOException, ServletException {
		if ((fi.getRequest() != null)
				&& (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
				&& observeOncePerRequest) {
			// filter already applied to this request and user wants us to observe
			// once-per-request handling, so don't re-do security checking
			fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
		}
		else {
			// first time this request being called, so perform security checking
			if (fi.getRequest() != null && observeOncePerRequest) {
				fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
			}

			InterceptorStatusToken token = super.beforeInvocation(fi);//表示查看之前的 filter 是否通过。

			try {
				fi.getChain().doFilter(fi.getRequest(), fi.getResponse());//表示真正的调用后台的服务。
			}
			finally {
				super.finallyInvocation(token);
			}

			super.afterInvocation(token, null);
		}
	}
```

该过滤器用于控制method级别的权限控制. 官方提供了2种默认的方法权限控制写法
一种是在方法上加注释实现, 另一种是在configure配置中通过

```java
//方法1, 方法定义处加注释, 需先在具体的配置里开启此类配置
@Secured("ROLE_ADMIN") 
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
	
//方法2, 在配置类中复写的configure里直接定义
.antMatchers("your match rule").authenticated()
.antMatchers("your match rule").hasRole("ADMIN") //使用时权限会自动加前缀ROLE_ADMIN
123456
```

上面两种方法最终都会生成一个**FilterSecurityInterceptor**实例, 放在上面过滤链底部。 用于方法级的鉴权。

#### 3.1.2ExceptionTranslationFilter

​	这是一个异常过滤器，用来处理认证授权过程中抛出的异常。

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		try {
			chain.doFilter(request, response);//1.调用过滤器链后面的filter

			logger.debug("Chain processed normally");
		}
		catch (IOException ex) {
			throw ex;
		}
		catch (Exception ex) {
			// Try to extract a SpringSecurityException from the stacktrace
			Throwable[] causeChain = throwableAnalyzer.determineCauseChain(ex);
			RuntimeException ase = (AuthenticationException) throwableAnalyzer
					.getFirstThrowableOfType(AuthenticationException.class, causeChain);//2.如果1中的操作抛出异常，就会来到此处，判断抛出的异常是否是AuthenticationException。
			
			if (ase == null) {	
				ase = (AccessDeniedException) throwableAnalyzer.getFirstThrowableOfType(
						AccessDeniedException.class, causeChain);//3.如果2不是AuthenticationException，也就是ase==null，就会判断是否为AccessDeniedException
			}

			if (ase != null) {
				if (response.isCommitted()) {
					throw new ServletException("Unable to handle the Spring Security Exception because the response is already committed.", ex);
				}
				handleSpringSecurityException(request, response, chain, ase);//如果抛出的异常是AuthenticationException或者时AccessDeniedException，那么执行此处的代码。
			}
			else {
				// Rethrow ServletExceptions and RuntimeExceptions as-is
				if (ex instanceof ServletException) {
					throw (ServletException) ex;
				}
				else if (ex instanceof RuntimeException) {
					throw (RuntimeException) ex;
				}

				// Wrap other Exceptions. This shouldn't actually happen
				// as we've already covered all the possibilities for doFilter
				throw new RuntimeException(ex);
			}
		}
	}
```

通过源码可知，该过滤器就是对认证授权中抛出的各种异常进行相应处理。

#### 3.1.3UsernamePasswordAuthenticationFilter

该过滤器主要是对login对的POST请求做拦截，校验表单用户名和密码。

```java
public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
		if (postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException(
					"Authentication method not supported: " + request.getMethod());
		}

		String username = obtainUsername(request);
		String password = obtainPassword(request);

		if (username == null) {
			username = "";
		}

		if (password == null) {
			password = "";
		}

		username = username.trim();

		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
				username, password);

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

		return this.getAuthenticationManager().authenticate(authRequest);
	}
```



### 3.2两个重要接口

**UserDetailsService**

UserDetailsService是SpringSecurity提供的概念模型接口，该接口用于查询数据库用户名和密码的过程。

\- 创建继承UsernamePasswordAuthenticationFilter，重写三个方法；

\- 创建类实现UserDetailService，编写查询数据库过程，返回User对象，这个User对象是安全框架提供对象。

**PasswordEncoder**

这是一个数据加密接口，用于返回User对象里面密码加密。

### **3.3设置登录认证信息**

在我们进行用户认证时，需要设置登陆时的用户名和密码。在SpringSecurity有三种方式可以设置：

- 通过配置文件
- 通过配置类
- 自定义编写实现类

#### 3.1.1通过配置文件

可以通过在application.properties中设置我们的用户名和密码，如下：

```java
#设置用户登录的用户名和密码
#spring.security.user.name=admin
#spring.security.user.password=123
```

#### 3.1.2通过配置类

通过配置类继承WebSecurityConfigurerAdapter，重写configure方法的方式。

```java
package com.hexin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * spring security配置类
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String password = passwordEncoder.encode("123");
        auth.inMemoryAuthentication().withUser("admin").password(password).roles("admin");
    }

    @Bean
    PasswordEncoder password(){
        return new BCryptPasswordEncoder();
    }
}

```

#### 3.1.3自定义实现类

具体步骤如下：

1）创建配置类，同样需要继承WebSecurityConfigurerAdapter，还要设置UserDetailsService实现类。

```java
package com.hexin.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(password());
    }

    @Bean
    PasswordEncoder password() {
        return new BCryptPasswordEncoder();
    }
}
```

2）编写UserDetailsService实现类，用于获取User对象，User对象有用户名密码和操作权限。

```java
package com.hexin.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("role");
        return new User("admin", new BCryptPasswordEncoder().encode("123"), authorities);
    }

}
```

### 3.4基于数据库的用户认证

​	以上方式都是我们通过设置固定的用户名和密码来作为登陆认证的信息，但是很多情况下用户登录信息是保存到数据库中，也就需要我们通过查询数据库来完成认证的过程。下面我们演示通过整合MybatisPlus来查询数据库完成认证。

#### 3.4.1代码实现

第一步：引入MabatisPlus相关依赖；

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.example</groupId>
    <artifactId>springsecuritylearn</artifactId>
    <version>1.0-SNAPSHOT</version>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.2.1.RELEASE</version>
        <relativePath/>
    </parent>

    <properties>
        <java.version>1.8</java.version>
    </properties>

    <dependencies>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <!--spring security-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <!--mybatis-plus-->
        <dependency>
            <groupId>com.baomidou</groupId>
            <artifactId>mybatis-plus-boot-starter</artifactId>
            <version>3.0.5</version>
        </dependency>
        <!--mysql-->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
        </dependency>
        <!--lombok 用来简化实体类-->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

第二步：创建数据库和表；	

```sql
create table users(
 id bigint primary key auto_increment,
username varchar(20) unique not null,
password varchar(100)
);
-- 密码 atguigu
insert into users values(1,'张
san','$2a$10$2R/M6iU3mCZt3ByG7kwYTeeW0w7/UqdeXrb27zkBIizBvAven0/na');
-- 密码 atguigu
insert into users values(2,'李
si','$2a$10$2R/M6iU3mCZt3ByG7kwYTeeW0w7/UqdeXrb27zkBIizBvAven0/na');
create table role(
id bigint primary key auto_increment,
name varchar(20)
);
insert into role values(1,'管理员');
insert into role values(2,'普通用户');
create table role_user(
uid bigint,
rid bigint
);
insert into role_user values(1,1);
insert into role_user values(2,2);
create table menu(
id bigint primary key auto_increment,
name varchar(20),
url varchar(100),
parentid bigint,
permission varchar(20)
);
insert into menu values(1,'系统管理','',0,'menu:system');
insert into menu values(2,'用户管理','',0,'menu:user');
create table role_menu(
mid bigint,
rid bigint
);
insert into role_menu values(1,1);
insert into role_menu values(2,1);
insert into role_menu values(2,2);
```

第三步：配置数据库信息。

```properties
server.port=8001
        
#配置文件添加数据库配置
#mysql 数据库连接
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver 
spring.datasource.url=jdbc:mysql://localhost:3306/springseccurity?serverTimezone=GMT%2B8 
spring.datasource.username=root 
spring.datasource.password=123456

#设置用户登录的用户名和密码
#spring.security.user.name=admin
#spring.security.user.password=123
```

第四步：创建user表和对应的实体类；

```java
package com.hexin.entity;

import lombok.Data;

@Data
public class User {
    private Integer id;
    private String username;
    private String password;
}

```

第五步：整合mapper，创建接口，继承mapper接口；

```java
package com.hexin.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.hexin.entity.User;

public interface UserMapper extends BaseMapper<User> {
}

```

第六步：在自定义实现类MyUserDetailsService调用mapper里面的方法来查询数据库，然后进行认证；

```java
package com.hexin.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.hexin.entity.User;
import com.hexin.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("role");
//        return new User("admin", new BCryptPasswordEncoder().encode("123"), authorities);
        //调用userMapper方法，根据用户名查询数据库中用户信息
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.eq("username", username);
        User user = userMapper.selectOne(wrapper);
        if (user == null){
            throw new UsernameNotFoundException("用户不存在！");
        }
        List<GrantedAuthority> grantedAuthorityList =
                AuthorityUtils.commaSeparatedStringToAuthorityList("role");
        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                new BCryptPasswordEncoder().encode(user.getPassword()), grantedAuthorityList);
    }

}
```

第七步：在启动类上添加注解MapperScan，指定Mapper需要扫描的包；

```java
package com.hexin;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@MapperScan("com.hexin.mapper")
@SpringBootApplication
public class SpringSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }
}
```

测试：

启动服务，输入用户名密码测试：



#### 3.4.2添加自定义登录页面

1）引入前端模板依赖

```xml
<!--java模板引擎-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
```

2）编写前端登录页面

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
    <form action="/user/login" method="post">
        用户名：<input type="text" name="username"/>
        <br/>
        密码：<input type="text" name="password"/>
        <br/>
        <input type="submit" value="login"/>
    </form>
</body>
</html>
```

3）编写控制器

```java
package com.hexin.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping("hello")
    public String Hello(){
        return "hello security!";
    }

    @GetMapping("index")
    public String index(){
        return "hello index!";
    }
}

```

4）编写配置类

​	编写配置类放行登录页面以及静态资源。

```java
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

@Configuration
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

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
        http.formLogin()    //自定义自己编写的登录页面
            .loginPage("/login.html")   //登录页面配置
            .loginProcessingUrl("/user/login")  //登录访问URL
            .defaultSuccessUrl("/test/index").permitAll()   //登录成功后的跳转路径
            .and().authorizeRequests()
                .antMatchers("/","/test/hello","/use/login").permitAll()//设置不需要认证的路径
            .anyRequest().authenticated()
            .and().csrf().disable();    //关闭csrf防护
    }

}
```

测试：

![image-20210116103951471](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210116103951471.png)

输入用户名和密码，就可以正常登录了。

![image-20210116104743389](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210116104743389.png)



### 3.5基于角色或权限的访问控制

#### 3.5.1hasAuthority方法

如果当前的用户具有指定的权限，则返回true，否则返回false。

页面表现：403，没有访问权限。（type=Forbidden,status=403）

具体设置：

```java
@Override
    protected void configure(HttpSecurity http) throws Exception{
        http.formLogin()    //自定义自己编写的登录页面
            .loginPage("/login.html")   //登录页面配置
            .loginProcessingUrl("/user/login")  //登录访问URL
            .defaultSuccessUrl("/test/index").permitAll()   //登录成功后的跳转路径
            .and().authorizeRequests()
                .antMatchers("/","/test/hello","/use/login").permitAll()    //设置不需要认证的路径
                //当前登陆的用户只有admins权限才可以访问
                .antMatchers("/test/index").hasAuthority("admins") //需要admins权限
                .anyRequest().authenticated()
            .and().csrf().disable();    //关闭csrf防护
    }
```

同属需要在MyUserDetailsService.java中为用户添加相应权限：

```java
@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("role");
//        return new User("admin", new BCryptPasswordEncoder().encode("123"), authorities);
        //调用userMapper方法，根据用户名查询数据库中用户信息
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.eq("username", username);
        User user = userMapper.selectOne(wrapper);
        if (user == null){
            throw new UsernameNotFoundException("用户不存在！");
        }
        //为用户添加相应的权限
        List<GrantedAuthority> grantedAuthorityList =
                AuthorityUtils.commaSeparatedStringToAuthorityList("role,admins");//加上admins权限
        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                new BCryptPasswordEncoder().encode(user.getPassword()), grantedAuthorityList);
    }
```

测试：

![image-20210116111848623](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210116111848623.png)

可以正常访问。

如果我们不为用户添加admins权限，就会的得到403无权限访问的错误。如下：

![image-20210116111545516](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210116111545516.png)

#### 3.5.2hasAnyAuthority方法

如果当前的用户有任何提供的角色（给定的作为一个逗号分隔的字符串列表）的话，返回true。

具体设置：

```java
//需要带有admins或test中任意一个权限
.antMatchers("/test/index").hasAnyAuthority("admins,test") 
```

#### 3.5.3hasRole方法

如果当前用户具有指定的角色，则返回true。

具体设置：

```java
//需要用户带有角色role1
.antMatchers("/test/index").hasRole("role1")
```

同时需要设置用户角色权限：

```java
List<GrantedAuthority> grantedAuthorityList =
                AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_role1");
```

#### 3.5.4hasAnyRole方法

标识用户具备热呢一个条件都可以访问。

具体配置：

```
//需要用户带有角色role1
                .antMatchers("/test/index").hasAnyRole("role1,admin")
```



### 3.6基于数据库的权限控制

​	之前小节中，我们都是通过在UserDetailsService实现类中，手动为用户添加角色和权限，但是在实际场景中我们都是通过查询数据库来获取某个用户的角色和权限，下面我们演示如何通过数据库进行权限控制。

#### 3.6.1代码实现

1）添加实体类

添加角色类

```java
package com.hexin.entity;

import lombok.Data;

@Data
public class Role {
    private Integer id;
    private String name;
}
```

添加权限（这里我们用菜单标识权限）类

```java
package com.hexin.entity;

import lombok.Data;

@Data
public class Menu {
    private Integer id;
    private String name;
    private String url;
    private Long parentId;
    private String permission;
}
```

2）编写持久层接口和Mapper映射文件

UserMapper接口

```java
package com.hexin.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.hexin.entity.Menu;
import com.hexin.entity.Role;
import com.hexin.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface UserMapper extends BaseMapper<User> {

    /**
     * 根据用户 Id 查询用户角色
     * @param userId
     * @return
     */
    @Select("SELECT r.id,r.name FROM role r INNER JOIN role_user ru " +
            "ON ru.rid=r.id where ru.uid=#{0}")
    List<Role> selectRoleByUserId(Integer userId);
    /**
     * 根据用户 Id 查询菜单
     * @param userId
     * @return
     */
    @Select("SELECT m.id,m.name,m.url,m.parentid,m.permission FROM menu m" +
            " INNER JOIN role_menu rm ON m.id=rm.mid" +
            " INNER JOIN role r ON r.id=rm.rid" +
            " INNER JOIN role_user ru ON r.id=ru.rid" +
            " WHERE ru.uid=#{0}")
    List<Menu> selectMenuByUserId(Integer userId);

}

```

3）新建UsersService接口实现类

​	这里需要把我们项目中原来的实现类MyUserDetailsService暂时注释掉。新建一个UsersServiceImpl，用于查询数据库获取用户角色和权限。

UsersServiceImpl

```java
package com.hexin.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.hexin.entity.Menu;
import com.hexin.entity.Role;
import com.hexin.entity.User;
import com.hexin.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UsersServiceImpl implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("通过数据库查询用户信息。");
        //调用userMapper方法，根据用户名查询数据库中用户信息
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.eq("username", username);
        User user = userMapper.selectOne(wrapper);
        if (user == null){
            System.out.println("用户不存在！");
            throw new UsernameNotFoundException("用户名不存在！");
        }
        //获取用户角色和菜单信息
        List<Role> roles = userMapper.selectRoleByUserId(user.getId());
        System.out.println(roles);
        List<Menu> menus = userMapper.selectMenuByUserId(user.getId());
        System.out.println(menus);
        //声明一个集合List<GrantedAuthority>
        List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
        //处理角色
        for (Role role : roles){
            SimpleGrantedAuthority simpleGrantedAuthority
                    = new SimpleGrantedAuthority("ROLE_"+role.getName());
            grantedAuthorityList.add(simpleGrantedAuthority);
        }
        for (Menu menu : menus){
            grantedAuthorityList.add(new SimpleGrantedAuthority(menu.getPermission()));
        }
        System.out.println(grantedAuthorityList);
        //将用户信息添加到当前用户中
        return new org.springframework.security.core.userdetails.User(username,
                new BCryptPasswordEncoder().encode(user.getPassword()),grantedAuthorityList);
    }
}
```

4)添加控制器

```java
package com.hexin.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FindController {

    @GetMapping("/findAll")
    public String findAll(){
        return "find all!";
    }

    @GetMapping("/find")
    public String index(){
        return "find!";
    }
}
```

5）修改访问配置类

```java
 .antMatchers("/findall").hasRole("管理员")
 .antMatchers("/find").hasAnyAuthority("menu:system")
```

![image-20210116171437386](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210116171437386.png)

6）使用管理员和非管理员进行测试

使用管理员：

![image-20210116202627020](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210116202627020.png)

使用非管理员：

![image-20210116202728499](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210116202728499.png)

#### 3.6.2自定义403页面

​	在5.3节中我们演示类基于权限访问控制的四个方法，我们发现当用户没有访问权限时，会直接显示默认的403界面给用户，很不友好。所以本小节我们自定义我们自己的403页面。

1）创建自定义的403页面

```html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Title</title>
    </head>
    <body>
        <h1>对不起，您没有访问权限！</h1>
    </body>
</html>
```

2）在配置类中配置

```java
 //配置没有权限时跳转到指定页面（代替默认403页面）
http.exceptionHandling().accessDeniedPage("/unauth.html");
```

![](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210116202956878.png)

再次使用无权限用户访问测试：

![image-20210116162246880](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210116162246880.png)

#### 3.6.3注解的使用

1）@Secured

该注解表示当用户具有某个角色时，可以访问某方法。

使用：

首先需要在启动类（配置类）上开启注解。

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
```

![image-20210116203602519](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210116203602519.png)

然后在Controller的方法上使用注解，设置角色：

```java
  @GetMapping("Secured")
    @Secured("ROLE_user,ROLE_管理员")
    public String update(){
        return "Secured !";
    }
```

3、UserDetailsService实现类中设置对应的用户角色

```java
List<GrantedAuthority> grantedAuthorityList =
                AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_role,ROLE_管理员");
```

由于我们是从数据库中获取角色，所以确保数据库中用户角色存在即可。

2）@PreAuthorize

​	该注解是在进入方法前的权限验证，同时可以将登录用户的 roles/permissions 参数传到方法中。

```java
@RequestMapping("/preAuthorize")
    @PreAuthorize("hasAnyAuthority('menu:system')")
    public String preAuthorize(){
        System.out.println("preAuthorize");
        return "preAuthorize";
    }
```

3）@PostAuthorize

该注解注解使用并不多，在方法执行后再进行权限验证，适合验证带有返回值的权限。

```
 @RequestMapping("/testPostAuthorize")
    @PostAuthorize("hasAnyAuthority('menu:system')")
    public String PostAuthorize(){
        System.out.println("test--PostAuthorize");
        return "PostAuthorize"; 
    }
}
```

4）PostFilter

​	该注解的作用是对方法返回的数据进行过滤。

```java
@RequestMapping("getAll")
    @PreAuthorize("hasRole('ROLE_管理员')")
    @PostFilter("filterObject.username == 'admin1'") //在校验之后进行过滤，留下用户admin1返回给前端
    @ResponseBody
    public List<User> getAllUser() {
        ArrayList<User> list = new ArrayList<>();
        list.add(new User(1, "admin1", "6666"));
        list.add(new User(2, "admin2", "888"));
        return list;
    }
```

5）PreFilter

​	该注解的作用是对传入的数据进行过滤。

```java
@RequestMapping("getTestPreFilter")
    @PreAuthorize("hasRole('ROLE_管理员')")
    @PreFilter(value = "filterObject.id%2==0")  //过滤用户id为偶数
    @ResponseBody
    public List<User> getTestPreFilter(@RequestBody List<User> list){
        list.forEach(t-> {
            System.out.println(t.getId()+"\t"+t.getUsername());
        });
        return list;
    }
```



### 3.7用户注销

​	1）实现用户注销需要再配置类中添加退出的配置，如下：

```java
//配置用户注销
http.logout()
    .logoutUrl("/logout")   //用户注销的url
    .logoutSuccessUrl("/test/hello").permitAll();
```

​	![image-20210117091412579](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210117091412579.png)

​	2）新建用户登录成功页面并添加注销按钮

```html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Title</title>
    </head>
    <body>
        登录成功<br>
        <a href="/logout">退出</a>
    </body>
</html>
```

3）我们还需要修改一个配置，将我们登录成功后跳转到success.html页面

```java
http.formLogin()    //自定义自己编写的登录页面
    .loginPage("/login.html")   //登录页面配置
    .loginProcessingUrl("/user/login")  //登录访问URL
    .defaultSuccessUrl("/success.html").permitAll()   //登录成功后的跳转路径
```

![image-20210117092959082](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210117092959082.png)

测试：

​	首先登录；

![image-20210117093054498](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210117093054498.png)

​	然后点击退出，并访问其他controller。

![image-20210117093150606](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210117093150606.png)

发现一家不能正常访问了。

### 3.8基于数据库实现记住我

#### 3.8.1实现原理

​	“记住我”的功能主要是依赖浏览器的cookie技术，下面我们用一张图简单说明一下原理：

![img](D:\data\youdaoNote\weixinobU7VjoqKsPIOC3vcNuosN7uJCCM\d19a9f8a54bb4225a96da4ff5ed2b1b4\clipboard.png)

1、客户端发出认证请求，服务端UsernamePasswordAuthenticationFilter过滤器拦截到请求并进行认证处理；

2、认证成功后，会进入RemeberMeService处理业务；

3、然后将Token写入浏览器的Cookie中，同时将Token信息写入到数据库中进行保存；

4、当用户之后的请求会被RememberMeAuthenticationFilter过滤器拦截，获取Cookie中的Token信息并与数据看比对，比对成功就会进行后续处理。

#### 3.8.2具体实现

1）新建表persistent_logins

该表用于保存用户登录后的token及过期时间等信息

```sql
CREATE TABLE `persistent_logins` (
 `username` varchar(64) NOT NULL,
 `series` varchar(64) NOT NULL,
 `token` varchar(64) NOT NULL,
 `last_used` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE 
CURRENT_TIMESTAMP,
 PRIMARY KEY (`series`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

2）修改配置类

```java
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
```

![](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210117100343119.png)

3）修改配置中的自动登录

```java
 .and().rememberMe().tokenRepository(persistentTokenRepository())  //设置自动登录
                  .tokenValiditySeconds(60) //有效时长60s
                  .userDetailsService(userDetailsService)
```

![image-20210117101021303](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210117101021303.png)

4）页面添加记住我复选框

```html
记住我：<input type="checkbox"name="remember-me"title="记住密码"/><br/>
```

PS：此处name 属性值必须位 remember-me。不能改为其他值

![image-20210117101135967](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210117101135967.png)

测试：

先登录成功，然后关闭浏览器，重新打开发现依然可以访问。打开数据库也能看到一条记录。

![image-20210117102041032](C:\Users\admin\AppData\Roaming\Typora\typora-user-images\image-20210117102041032.png)




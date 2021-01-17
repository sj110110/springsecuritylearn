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

//@Service
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
                AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_role,ROLE_管理员");
        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                new BCryptPasswordEncoder().encode(user.getPassword()), grantedAuthorityList);
    }

}

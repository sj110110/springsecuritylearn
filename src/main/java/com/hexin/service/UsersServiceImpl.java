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
//        System.out.println(roles);
        List<Menu> menus = userMapper.selectMenuByUserId(user.getId());
//        System.out.println(menus);
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
//        System.out.println(grantedAuthorityList);
        //将用户信息添加到当前用户中
        return new org.springframework.security.core.userdetails.User(username,
                new BCryptPasswordEncoder().encode(user.getPassword()),grantedAuthorityList);
    }
}

package com.hexin.controller;

import com.hexin.entity.User;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping("hello")
    public String Hello(){
        return "success";
    }

    @GetMapping("index")
    public String index(){
        return "hello index!";
    }

    @GetMapping("Secured")
    @Secured("ROLE_user,ROLE_管理员")
    public String update(){
        return "Secured !";
    }

    @RequestMapping("/preAuthorize")
    @PreAuthorize("hasAnyAuthority('menu:system')")
    public String preAuthorize(){
        System.out.println("preAuthorize");
        return "preAuthorize";
    }

    @RequestMapping("/testPostAuthorize")
    @PostAuthorize("hasAnyAuthority('menu:system')")
    public String PostAuthorize(){
        System.out.println("test--PostAuthorize");
        return "PostAuthorize";
    }

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
}

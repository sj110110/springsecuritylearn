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

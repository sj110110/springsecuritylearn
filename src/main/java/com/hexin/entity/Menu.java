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

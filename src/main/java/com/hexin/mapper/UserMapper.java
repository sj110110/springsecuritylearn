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

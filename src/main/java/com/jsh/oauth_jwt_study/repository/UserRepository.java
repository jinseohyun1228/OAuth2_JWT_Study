package com.jsh.oauth_jwt_study.repository;

import com.jsh.oauth_jwt_study.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    UserEntity findByUsername(String username);
}
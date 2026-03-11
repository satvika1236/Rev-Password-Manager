package com.revature.passwordmanager.repository;

import com.revature.passwordmanager.model.auth.TwoFactorAuth;
import com.revature.passwordmanager.model.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TwoFactorAuthRepository extends JpaRepository<TwoFactorAuth, Long> {
  Optional<TwoFactorAuth> findByUser(User user);
}

package com.revature.passwordmanager.repository;

import com.revature.passwordmanager.model.user.RecoveryCode;
import com.revature.passwordmanager.model.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RecoveryCodeRepository extends JpaRepository<RecoveryCode, Long> {
  List<RecoveryCode> findByUser(User user);

  boolean existsByCodeHash(String codeHash);
}

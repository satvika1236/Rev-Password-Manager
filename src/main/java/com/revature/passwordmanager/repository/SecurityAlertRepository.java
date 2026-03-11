package com.revature.passwordmanager.repository;

import com.revature.passwordmanager.model.security.SecurityAlert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, Long> {

  List<SecurityAlert> findByUserIdOrderByCreatedAtDesc(Long userId);

  long countByUserIdAndIsReadFalse(Long userId);

  List<SecurityAlert> findByUserIdAndIsReadFalseOrderByCreatedAtDesc(Long userId);
}

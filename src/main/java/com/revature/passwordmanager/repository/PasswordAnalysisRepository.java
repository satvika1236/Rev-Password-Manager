package com.revature.passwordmanager.repository;

import com.revature.passwordmanager.model.security.PasswordAnalysis;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PasswordAnalysisRepository extends JpaRepository<PasswordAnalysis, Long> {
  Optional<PasswordAnalysis> findByVaultEntryId(Long vaultEntryId);

  List<PasswordAnalysis> findByVaultEntryUserId(Long userId);

  void deleteByVaultEntryId(Long vaultEntryId);
}

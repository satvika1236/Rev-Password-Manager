package com.revature.passwordmanager.repository;

import com.revature.passwordmanager.model.backup.BackupExport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface BackupExportRepository extends JpaRepository<BackupExport, Long> {
  List<BackupExport> findByUserIdOrderByCreatedAtDesc(Long userId);
}

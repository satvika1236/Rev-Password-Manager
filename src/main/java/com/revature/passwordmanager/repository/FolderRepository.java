package com.revature.passwordmanager.repository;

import com.revature.passwordmanager.model.vault.Folder;
import com.revature.passwordmanager.model.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface FolderRepository extends JpaRepository<Folder, Long> {
  List<Folder> findByUserAndParentFolderIsNull(User user);

  List<Folder> findByUser(User user);

  Optional<Folder> findByIdAndUser(Long id, User user);

  int countByUser(User user);
}

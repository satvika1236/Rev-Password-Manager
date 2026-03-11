package com.revature.passwordmanager.repository;

import com.revature.passwordmanager.model.security.AuditLog;
import com.revature.passwordmanager.model.security.AuditLog.AuditAction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

  List<AuditLog> findByUserIdOrderByTimestampDesc(Long userId);

  List<AuditLog> findByUserIdAndTimestampAfter(Long userId, LocalDateTime timestamp);

  /** Returns all audit logs for a user within a date range, ordered newest first. */
  List<AuditLog> findByUserIdAndTimestampBetweenOrderByTimestampDesc(
      Long userId, LocalDateTime start, LocalDateTime end);

  /** Returns audit logs for a user filtered by a specific action type, newest first. */
  List<AuditLog> findByUserIdAndActionOrderByTimestampDesc(Long userId, AuditAction action);

  /** Returns audit logs for a user filtered by a set of actions, newest first. */
  @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.action IN :actions " +
         "ORDER BY a.timestamp DESC")
  List<AuditLog> findByUserIdAndActionInOrderByTimestampDesc(
      @Param("userId") Long userId,
      @Param("actions") List<AuditAction> actions);

  /** Returns audit logs for a user filtered by action and timestamp range, newest first. */
  @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId AND a.action IN :actions " +
         "AND a.timestamp BETWEEN :start AND :end ORDER BY a.timestamp DESC")
  List<AuditLog> findByUserIdAndActionInAndTimestampBetween(
      @Param("userId") Long userId,
      @Param("actions") List<AuditAction> actions,
      @Param("start") LocalDateTime start,
      @Param("end") LocalDateTime end);

  /** Counts total audit log entries for a user. */
  long countByUserId(Long userId);

  /** Counts audit log entries for a user after a given timestamp. */
  long countByUserIdAndTimestampAfter(Long userId, LocalDateTime after);
}

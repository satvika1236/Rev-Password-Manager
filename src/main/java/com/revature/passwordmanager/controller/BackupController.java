package com.revature.passwordmanager.controller;

import com.revature.passwordmanager.dto.request.ImportRequest;
import com.revature.passwordmanager.dto.request.ThirdPartyImportRequest;
import com.revature.passwordmanager.dto.response.ExportResponse;
import com.revature.passwordmanager.dto.response.ImportResult;
import com.revature.passwordmanager.service.backup.ExportService;
import com.revature.passwordmanager.service.backup.ImportService;
import com.revature.passwordmanager.service.backup.ThirdPartyImportService;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/backup")
@RequiredArgsConstructor
public class BackupController {

  private static final Logger logger = LoggerFactory.getLogger(BackupController.class);

  private final ExportService exportService;
  private final ImportService importService;
  private final ThirdPartyImportService thirdPartyImportService;
  private final com.revature.passwordmanager.service.vault.VaultSnapshotService vaultSnapshotService;

  @GetMapping("/export")
  public ResponseEntity<ExportResponse> exportVault(
      @RequestParam(defaultValue = "JSON") String format,
      @RequestParam(required = false) String password) {
    String username = getCurrentUsername();
    return ResponseEntity.ok(exportService.exportVault(username, format, password));
  }

  @PostMapping("/import")
  public ResponseEntity<ImportResult> importVault(@RequestBody ImportRequest request) {
    logger.info("Import request received in controller");
    logger.debug("Request format: {}, data length: {}",
        request.getFormat(),
        request.getData() != null ? request.getData().length() : 0);
    String username = getCurrentUsername();
    return ResponseEntity.ok(importService.importVault(username, request));
  }

  @PostMapping("/import-external")
  public ResponseEntity<ImportResult> importFromExternal(@RequestBody ThirdPartyImportRequest request) {
    String username = getCurrentUsername();
    return ResponseEntity.ok(thirdPartyImportService.importFromThirdParty(username, request));
  }

  @GetMapping("/export/preview")
  public ResponseEntity<ExportResponse> previewExport(@RequestParam(defaultValue = "JSON") String format) {
    String username = getCurrentUsername();
    return ResponseEntity.ok(exportService.previewExport(username, format));
  }

  @PostMapping("/import/validate")
  public ResponseEntity<ImportResult> validateImport(@RequestBody ImportRequest request) {
    String username = getCurrentUsername();
    return ResponseEntity.ok(importService.validateImport(username, request));
  }

  @GetMapping("/import-external/formats")
  public ResponseEntity<java.util.List<String>> getSupportedFormats() {
    return ResponseEntity.ok(thirdPartyImportService.getSupportedFormats());
  }

  @GetMapping("/snapshots")
  public ResponseEntity<java.util.List<com.revature.passwordmanager.dto.response.SnapshotResponse>> getAllSnapshots() {
    String username = getCurrentUsername();
    return ResponseEntity.ok(vaultSnapshotService.getAllSnapshots(username));
  }

  @PostMapping("/snapshots/{id}/restore")
  public ResponseEntity<Void> restoreSnapshot(@PathVariable Long id) {
    String username = getCurrentUsername();
    vaultSnapshotService.restoreSnapshot(username, id);
    return ResponseEntity.ok().build();
  }

  private String getCurrentUsername() {
    return SecurityContextHolder.getContext().getAuthentication().getName();
  }
}

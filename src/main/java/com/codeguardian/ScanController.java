package com.codeguardian;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Controller
public class ScanController {

    private String lastUploadedCode;
    private String lastUploadedFileName;

    // =========================
    // HOME PAGE
    // =========================

    @GetMapping("/")
    public String home() {
        return "index";
    }

    // =========================
    // FILE UPLOAD + SCAN
    // =========================

    @PostMapping({"/scan", "/api/upload"})
    public String scanFile(
            @RequestParam("file") MultipartFile file,
            Model model) {

        try {

            if (file == null || file.isEmpty()) {
                model.addAttribute("error", "Please upload a Java file.");
                return "index";
            }

            String code = new String(
                    file.getBytes(),
                    StandardCharsets.UTF_8
            );

            lastUploadedCode = code;
            lastUploadedFileName = file.getOriginalFilename();

            List<Vulnerability> vulnerabilities =
                    detectVulnerabilities(code);

            // File name
            model.addAttribute(
                    "fileName",
                    lastUploadedFileName
            );

            // Vulnerability list
            model.addAttribute(
                    "vulnerabilities",
                    vulnerabilities
            );

            // Total vulnerability count
            model.addAttribute(
                    "vulnerabilityCount",
                    vulnerabilities.size()
            );

            // =========================
            // SEVERITY COUNTS
            // =========================

            long highCount = vulnerabilities.stream()
                    .filter(v -> "HIGH".equals(v.getSeverity()))
                    .count();

            long mediumCount = vulnerabilities.stream()
                    .filter(v -> "MEDIUM".equals(v.getSeverity()))
                    .count();

            long lowCount = vulnerabilities.stream()
                    .filter(v -> "LOW".equals(v.getSeverity()))
                    .count();

            model.addAttribute(
                    "highCount",
                    highCount
            );

            model.addAttribute(
                    "mediumCount",
                    mediumCount
            );

            model.addAttribute(
                    "lowCount",
                    lowCount
            );

            return "report";

        } catch (Exception e) {

            model.addAttribute(
                    "error",
                    "Error while scanning file: " + e.getMessage()
            );

            return "index";
        }
    }

    // =========================
    // VULNERABILITY DETECTION
    // =========================

    private List<Vulnerability> detectVulnerabilities(String code) {

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        String[] lines = code.split("\\R");

        // =================================
        // 1. HARD CODED CREDENTIAL
        // =================================

        for (int i = 0; i < lines.length; i++) {

            String line = lines[i];

            if (line.matches(
                    ".*(password|passwd|pwd|secret|apiKey|api_key).*=" +
                            "\\s*\"[^\"]+\".*")) {

                vulnerabilities.add(
                        new Vulnerability(
                                "Hardcoded Credential",
                                "MEDIUM",
                                i + 1,
                                "A password or credential appears to be directly stored in the source code.",
                                """
                                Recommended secure approach:

                                Replace hardcoded credentials with environment variables.

                                Example:

                                String password = System.getenv("DB_PASSWORD");

                                Reason:
                                Credentials should not be stored directly inside source code.
                                """
                        )
                );

                break;
            }
        }

        // =================================
        // 2. SQL INJECTION
        // =================================

        for (int i = 0; i < lines.length; i++) {

            String line = lines[i];

            if ((line.contains("SELECT")
                    || line.contains("INSERT")
                    || line.contains("UPDATE")
                    || line.contains("DELETE"))
                    && line.contains("+")) {

                vulnerabilities.add(
                        new Vulnerability(
                                "SQL Injection",
                                "HIGH",
                                i + 1,
                                "SQL query appears to be constructed using string concatenation with user-controlled data.",
                                """
                                Recommended secure approach:

                                Use PreparedStatement instead of string concatenation.

                                Example:

                                String query =
                                    "SELECT * FROM users WHERE username = ?";

                                PreparedStatement stmt =
                                    conn.prepareStatement(query);

                                stmt.setString(1, username);

                                Reason:
                                Parameterized queries prevent malicious input from
                                changing the SQL command.
                                """
                        )
                );

                break;
            }
        }

        // =================================
        // 3. COMMAND INJECTION
        // =================================

        for (int i = 0; i < lines.length; i++) {

            String line = lines[i];

            if (line.contains("Runtime.getRuntime().exec")
                    || line.contains("ProcessBuilder")) {

                vulnerabilities.add(
                        new Vulnerability(
                                "Command Injection",
                                "HIGH",
                                i + 1,
                                "The application appears to execute an operating-system command directly.",
                                """
                                Recommended secure approach:

                                Avoid executing shell commands using untrusted input.

                                Validate and allow-list input before executing
                                any system-level operation.

                                Reason:
                                Untrusted command arguments can allow attackers
                                to execute malicious operating-system commands.
                                """
                        )
                );

                break;
            }
        }

        // =================================
        // 4. WEAK HASHING
        // =================================

        for (int i = 0; i < lines.length; i++) {

            String line = lines[i];

            if (line.contains("MD5")
                    || line.contains("SHA1")
                    || line.contains("SHA-1")) {

                vulnerabilities.add(
                        new Vulnerability(
                                "Weak Hashing",
                                "MEDIUM",
                                i + 1,
                                "The code uses a cryptographically weak hashing algorithm.",
                                """
                                Recommended secure approach:

                                Replace MD5 or SHA-1 with SHA-256 or a stronger
                                modern password hashing algorithm.

                                Example:

                                SHA-256

                                Reason:
                                MD5 and SHA-1 are considered weak for modern
                                security-sensitive applications.
                                """
                        )
                );

                break;
            }
        }

        return vulnerabilities;
    }

    // =========================
    // APPLY AUTOMATIC FIXES
    // =========================

    private String applyFixes(String code) {

        String fixed = code;

        // =================================
        // HARD CODED PASSWORD FIX
        // =================================

        fixed = fixed.replaceAll(
                "(String\\s+password\\s*=\\s*)\"[^\"]*\"\\s*;",
                "$1System.getenv(\"DB_PASSWORD\");"
        );

        // =================================
        // HARD CODED PASSWD FIX
        // =================================

        fixed = fixed.replaceAll(
                "(String\\s+passwd\\s*=\\s*)\"[^\"]*\"\\s*;",
                "$1System.getenv(\"DB_PASSWORD\");"
        );

        // =================================
        // HARD CODED PWD FIX
        // =================================

        fixed = fixed.replaceAll(
                "(String\\s+pwd\\s*=\\s*)\"[^\"]*\"\\s*;",
                "$1System.getenv(\"DB_PASSWORD\");"
        );

        // =================================
        // WEAK HASHING FIX
        // =================================

        fixed = fixed.replace("MD5", "SHA-256");

        fixed = fixed.replace("SHA1", "SHA-256");

        fixed = fixed.replace("SHA-1", "SHA-256");

        // =================================
        // COMMON SQL CONCATENATION FIX
        // =================================

        fixed = fixed.replace(
                "\"SELECT * FROM users WHERE username='\" + username + \"'\"",
                "\"SELECT * FROM users WHERE username = ?\""
        );

        return fixed;
    }

    // =========================
    // DOWNLOAD FIXED CODE
    // =========================

    @GetMapping("/download-fix")
    public ResponseEntity<String> downloadFix() {

        if (lastUploadedCode == null
                || lastUploadedCode.isBlank()) {

            return ResponseEntity
                    .badRequest()
                    .body(
                            "No uploaded source code available. " +
                                    "Please upload a Java file first."
                    );
        }

        String fixedCode = applyFixes(lastUploadedCode);

        return ResponseEntity
                .ok()
                .header(
                        "Content-Disposition",
                        "attachment; filename=FixedCode.java"
                )
                .header(
                        "Content-Type",
                        "text/plain"
                )
                .body(fixedCode);
    }

    // =========================
    // VULNERABILITY CLASS
    // =========================

    public static class Vulnerability {

        private String type;
        private String severity;
        private int line;
        private String description;
        private String fix;

        public Vulnerability(
                String type,
                String severity,
                int line,
                String description,
                String fix) {

            this.type = type;
            this.severity = severity;
            this.line = line;
            this.description = description;
            this.fix = fix;
        }

        public String getType() {
            return type;
        }

        public String getSeverity() {
            return severity;
        }

        public int getLine() {
            return line;
        }

        public String getDescription() {
            return description;
        }

        public String getFix() {
            return fix;
        }
    }
}
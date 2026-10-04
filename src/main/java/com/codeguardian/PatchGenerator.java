package com.codeguardian;

public class PatchGenerator {

    public static String generateFix(String code, String vulnerability) {

        if (vulnerability.equals("SQL Injection")) {

            return """
                    Recommended secure approach:

                    Replace:

                    String query = "SELECT * FROM users WHERE username='" + username + "'";
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery(query);

                    With:

                    String query = "SELECT * FROM users WHERE username = ?";
                    PreparedStatement stmt = conn.prepareStatement(query);
                    stmt.setString(1, username);
                    ResultSet rs = stmt.executeQuery();

                    Reason:
                    PreparedStatement prevents SQL injection by separating SQL
                    instructions from user-supplied data.
                    """;
        }

        if (vulnerability.equals("Hardcoded Credential")) {

            return """
                    Recommended secure approach:

                    Replace hardcoded credentials with environment variables.

                    Example:

                    String password = System.getenv("DB_PASSWORD");

                    Reason:
                    Credentials should not be stored directly inside source code.
                    """;
        }

        if (vulnerability.equals("Command Injection")) {

            return """
                    Recommended secure approach:

                    Avoid Runtime.getRuntime().exec() with untrusted input.

                    Validate user input strictly and use a safer API instead.

                    Reason:
                    Untrusted input passed to operating-system commands can
                    allow command injection.
                    """;
        }

        if (vulnerability.equals("Weak Cryptography")) {

            return """
                    Recommended secure approach:

                    Replace MD5 or SHA-1 with a modern cryptographic algorithm.

                    For general hashing, prefer SHA-256 or stronger algorithms.

                    For p       assword storage, use a password hashing algorithm
                    such as Argon2, bcrypt, or scrypt.

                    Reason:
                    MD5 and SHA-1 are considered cryptographically weak.
                    """;
        }

        return "No automatic fix is currently available for this vulnerability.";
    }
}
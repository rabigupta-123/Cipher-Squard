import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

/**
 * Provisioner handles the "Zero-Config" startup sequence.
 * It ensures that the database schema is initialized, the root audit key is generated,
 * and a default administrative user exists before the server starts.
 */
public final class Provisioner {
    private static final Logger logger = Logger.getLogger(Provisioner.class.getName());

    public static void provision() {
        logger.info("Starting zero-config provisioning sequence...");

        try {
            // 1. Initialize data files / schemas
            Files.createDirectories(Paths.get("data"));
            new App.CaseStore(Paths.get("data", "cases.ndjson")).load();
            new Audit(Paths.get("data", "audit.ndjson"), Paths.get("data", "audit-sigs.ndjson"),
                      new Audit.KeyManager(Paths.get("data", "keys", "ed25519.pem")));
            logger.info("Data stores and audit chain initialized.");

            // 2. Ensure Audit Root Key exists
            Audit.KeyManager.createOrLoad(Paths.get("data", "keys", "ed25519.pem"));
            logger.info("Audit signing key verified/generated.");

            // 3. Bootstrap Admin User
            // Note: In a real deployment, the admin password would be generated and displayed once,
            // or read from an environment variable. For the "out-of-the-box" demo, we ensure
            // at least one analyst account exists.
            App app = new App(0);
            if (!app.auth().hasUser("admin")) {
                String envPw = System.getenv("CIPHER_BOOTSTRAP_PASSWORD");
                char[] pw;
                boolean isGenerated = false;
                if (envPw != null && envPw.length() >= 12) {
                    pw = envPw.toCharArray();
                } else {
                    byte[] rnd = new byte[16];
                    new java.security.SecureRandom().nextBytes(rnd);
                    pw = (java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(rnd) + "!9aZ").toCharArray();
                    isGenerated = true;
                }
                try {
                    app.auth().upsert("admin", pw, java.util.List.of("admin", "analyst"));
                    if (isGenerated) {
                        System.out.println("========================================================================");
                        System.out.println("[SECURITY] Generated single-use bootstrap admin password: " + new String(pw));
                        System.out.println("[SECURITY] Save this credential immediately. It will not be shown again.");
                        System.out.println("========================================================================");
                        logger.info("Admin account initialized with random single-use bootstrap password.");
                    } else {
                        logger.info("Admin account initialized from environment.");
                    }
                } finally {
                    java.util.Arrays.fill(pw, '\0');
                }
            } else {
                logger.info("Admin account already exists; preserving existing credentials.");
            }

        } catch (Exception e) {
            logger.severe("Provisioning failed: " + e.getMessage());
            throw new RuntimeException("system provisioning failed", e);
        }

        logger.info("Provisioning complete. System is ready for operational use.");
    }
}

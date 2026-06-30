// tests/fixtures/safe.java
//
// Benign Java patterns that must produce ZERO findings. These guard against
// false positives in the Java rules (deserialization / CORS / SSRF / CSRF / SQL).
import java.util.concurrent.ExecutorService;
import javax.crypto.Cipher;
import org.springframework.web.bind.annotation.CrossOrigin;

public class Safe {
    // Safe: algorithm loaded from config, not a literal
    public void configDrivenCipher(String algorithmFromConfig) throws Exception {
        Cipher.getInstance(algorithmFromConfig); // variable, not a string literal — should NOT fire
    }

    // Safe: readObject() on a custom, non-ObjectInputStream/XMLDecoder receiver.
    // The declared type is a benign deserializer, so no deserialization finding.
    public void customDeserialize(MyCustomSafeDeserializer myCustomSafeDeserializer) {
        myCustomSafeDeserializer.readObject();
    }

    // Safe: a specific, trusted origin — not a wildcard.
    @CrossOrigin(origins = "https://example.com")
    public void specificOrigin() {}

    // Safe: getForObject() on a non-RestTemplate receiver named *Template.
    public void notARestTemplate(MyTemplate myTemplate, String url) {
        myTemplate.getForObject(url, String.class);
    }

    // Safe: a disable() call that is NOT part of a Spring HttpSecurity chain.
    public void notHttpSecurityCsrf(SomeConfig config) {
        myCsrfHelper(config.disable());
    }

    private void myCsrfHelper(Object ignored) {}

    // Safe: ExecutorService.execute(Runnable) is NOT a JDBC sink. The lambda body
    // contains ordinary string-literal concatenation (e.g. a log message), which
    // must NOT be mistaken for a SQL query assembled with `+`. Guards the FP where
    // `execute` matched the SQL-method name and the old recursive concat check
    // descended into the lambda body.
    public void executorIsNotAJdbcSink(ExecutorService executor, String user) {
        executor.execute(() -> {
            String message = "proxying request for user: " + user;
            auditLog(message);
        });
    }

    private void auditLog(String ignored) {}
}

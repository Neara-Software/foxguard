public class SafeApexTaint {

    // Static SOQL with a bind variable — no dynamic query, no injection.
    public List<Account> bindSearch(String name) {
        return [SELECT Id, Name FROM Account WHERE Name = :name];
    }

    // Escaped input before building the dynamic query.
    public List<Account> escapedSearch(String name) {
        String clean = String.escapeSingleQuotes(name);
        String q = 'SELECT Id FROM Account WHERE Name = \'' + clean + '\'';
        return Database.query(q);
    }

    // Fully literal dynamic query — nothing untrusted flows in.
    public List<Account> literalQuery() {
        String q = 'SELECT Id, Name FROM Account LIMIT 50';
        return Database.query(q);
    }

    // Tainted parameter used only for logging, never a query sink.
    public void audit(String actor) {
        System.debug(LoggingLevel.INFO, 'actor=' + actor);
    }
}

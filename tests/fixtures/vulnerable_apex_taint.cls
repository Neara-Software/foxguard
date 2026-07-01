public class VulnerableApexTaint {

    // POSITIVE 1: untrusted method parameter concatenated into a dynamic SOQL
    // query and executed via Database.query.
    public List<Account> searchByName(String name) {
        String q = 'SELECT Id, Name FROM Account WHERE Name = \'' + name + '\'';
        return Database.query(q);
    }

    // POSITIVE 2: parameter flows directly into Database.query.
    public List<Contact> rawQuery(String soql) {
        return Database.query(soql);
    }

    // POSITIVE 3: Visualforce page parameter reaches Database.getQueryLocator.
    public Database.QueryLocator locateByPage() {
        String id = ApexPages.currentPage().getParameters().get('id');
        String q = 'SELECT Id FROM Account WHERE Id = \'' + id + '\'';
        return Database.getQueryLocator(q);
    }

    // POSITIVE 4: tainted parameter reaches Database.countQuery.
    public Integer countByName(String name) {
        String q = 'SELECT COUNT() FROM Account WHERE Name = \'' + name + '\'';
        return Database.countQuery(q);
    }

    // NEAR-MISS 1: input is escaped with String.escapeSingleQuotes before use.
    public List<Account> safeSearch(String name) {
        String clean = String.escapeSingleQuotes(name);
        String q = 'SELECT Id FROM Account WHERE Name = \'' + clean + '\'';
        return Database.query(q);
    }

    // NEAR-MISS 2: fully static/literal query — no untrusted input reaches the sink.
    public List<Account> allAccounts() {
        return Database.query('SELECT Id, Name FROM Account LIMIT 100');
    }

    // NEAR-MISS 3: tainted parameter never reaches a query sink.
    public void logName(String name) {
        System.debug('name=' + name);
    }
}

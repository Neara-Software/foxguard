// Vulnerable Scala/Play taint fixture.
//
// One true positive per first-party Scala taint rule. Play binds request
// query/form/path values to controller action parameters, so every parameter
// is treated as untrusted request input by the engine.
//
// Expected findings:
//   scala/taint-sql-injection      → line ~18 (stmt.executeQuery(concat))
//   scala/taint-command-injection  → line ~25 (Runtime.getRuntime.exec)
//   scala/taint-xss                → line ~32 (Html(concat))

package controllers

object VulnerableController {

  // SQL injection: request parameter concatenated into a JDBC query.
  def search(name: String) = Action {
    val stmt = conn.createStatement()
    val rows = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")
    Ok(rows.toString)
  }

  // Command injection: request parameter passed to Runtime.exec.
  def ping(host: String) = Action {
    Runtime.getRuntime.exec("ping -c 1 " + host)
    Ok("done")
  }

  // XSS: request parameter wrapped in Html without escaping.
  def greet(msg: String) = Action {
    Ok(Html("<h1>Hello " + msg + "</h1>"))
  }

  // ── Near-misses (must NOT fire) ──────────────────────────────────────────

  // Constant query, no parameter reaches the sink.
  def listAll() = Action {
    val stmt = conn.createStatement()
    val rows = stmt.executeQuery("SELECT * FROM users")
    Ok(rows.toString)
  }

  // Literal command argument, no request input.
  def uptime() = Action {
    Runtime.getRuntime.exec("uptime")
    Ok("done")
  }

  // Static HTML content, nothing tainted.
  def banner() = Action {
    Ok(Html("<h1>Welcome</h1>"))
  }
}

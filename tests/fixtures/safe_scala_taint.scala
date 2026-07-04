// Safe Scala/Play fixture — must produce ZERO Scala taint findings.
//
// Each handler either uses a parameterized query, a fixed executable with no
// request-controlled argument, or emits no request input into an HTML sink.

package controllers

object SafeController {

  // Parameterized query: the request value is bound, never concatenated.
  def search(name: String) = Action {
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?")
    stmt.setString(1, name)
    val rows = stmt.executeQuery()
    Ok(rows.toString)
  }

  // Fixed command, no request input flows into exec.
  def health() = Action {
    Runtime.getRuntime.exec("systemctl status app")
    Ok("ok")
  }

  // Static HTML, no tainted content.
  def home() = Action {
    Ok(Html("<h1>Home</h1>"))
  }

  // Request value used only for logging and a plain response — no sink.
  def echo(msg: String) = Action {
    logger.info("received: " + msg)
    Ok("received")
  }

  // Fixed file path — request input never reaches the file-open sink.
  def readme(name: String) = Action {
    Ok(Source.fromFile("/etc/motd").mkString)
  }

  // Fixed URL — request input never reaches the fetch sink.
  def fetch(target: String) = Action {
    Ok(ws.url("https://status.example.com").toString)
  }
}

using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Web;

// Negative fixture for the C# taint engine. Every method either uses a
// literal argument, has its taint killed by a sanitizer, or never lets the
// tainted value reach a sink. No csharp/taint-* rule may fire.

namespace SafeApp
{
    public class SafeController
    {
        // NEAR MISS: literal argument to a command sink.
        public void LiteralCommand()
        {
            Process.Start("notepad.exe");
        }

        // NEAR MISS: tainted value captured but the sink receives a literal.
        public void TaintNeverReachesSink()
        {
            string unused = Request.QueryString["ignored"];
            Response.Write("static content");
        }

        // NEAR MISS: HttpUtility.HtmlEncode sanitizes the flow before output.
        public void SanitizedXss()
        {
            string raw = Request.QueryString["q"];
            string safe = HttpUtility.HtmlEncode(raw);
            Response.Write(safe);
        }

        // NEAR MISS: int.Parse collapses taint to clean before SQL concat.
        public void NumericSqlSanitized()
        {
            string rawId = Request.QueryString["id"];
            int safeId = int.Parse(rawId);
            string sql = "SELECT * FROM Users WHERE Id = " + safeId;
            var cmd = new SqlCommand(sql);
            cmd.ExecuteReader();
        }

        // NEAR MISS: redirect to a fixed, allowlisted URL.
        public void FixedRedirect()
        {
            Response.Redirect("/home");
        }
    }
}

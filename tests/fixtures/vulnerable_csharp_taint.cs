using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Web;
using System.Xml;

// Positive fixture for the C# taint engine. Each method flows an
// ASP.NET request source (Request.QueryString / Form / Params) into a
// taint sink. The two `NearMiss*` methods at the bottom must NOT fire.

namespace VulnerableApp
{
    public class TaintController
    {
        // POSITIVE (csharp/taint-sql-injection):
        // Request.QueryString -> string concat -> SqlCommand ctor.
        public void SqlInjectionFlow()
        {
            string id = Request.QueryString["id"];
            string sql = "SELECT * FROM Users WHERE Id = " + id;
            var cmd = new SqlCommand(sql);
            cmd.ExecuteReader();
        }

        // POSITIVE (csharp/taint-command-injection):
        // Request.Form -> Process.Start.
        public void CommandInjectionFlow()
        {
            string cmd = Request.Form["cmd"];
            Process.Start(cmd);
        }

        // POSITIVE (csharp/taint-xss):
        // Request.QueryString -> Response.Write.
        public void XssFlow()
        {
            string raw = Request.QueryString["q"];
            Response.Write(raw);
        }

        // POSITIVE (csharp/taint-open-redirect):
        // Request.Params -> Response.Redirect.
        public void OpenRedirectFlow()
        {
            string url = Request.Params["returnUrl"];
            Response.Redirect(url);
        }

        // POSITIVE (csharp/taint-xxe):
        // Request.QueryString -> XmlDocument.LoadXml.
        public void XxeFlow()
        {
            string xml = Request.QueryString["xml"];
            var doc = new XmlDocument();
            doc.LoadXml(xml);
        }

        // POSITIVE (csharp/taint-unsafe-load):
        // Request.Form -> Assembly.Load. The xxe spec's `Load` sink was
        // receiver-less and matched `Assembly.Load(...)` too, producing a false
        // XXE; it has been constrained to XmlDocument.Load / XDocument.Load
        // receivers. This method asserts Assembly.Load fires unsafe-load only
        // (and does NOT also fire csharp/taint-xxe).
        public void UnsafeLoadFlow()
        {
            string typeName = Request.Form["type"];
            Assembly.Load(typeName);
        }

        // NEAR MISS: literal argument — no taint reaches the sink.
        public void NearMissLiteralCommand()
        {
            Process.Start("notepad.exe");
        }

        // NEAR MISS: tainted value captured but never reaches a sink; the
        // written value is a static literal.
        public void NearMissTaintNeverReachesSink()
        {
            string unused = Request.QueryString["ignored"];
            Response.Write("static content");
        }
    }
}

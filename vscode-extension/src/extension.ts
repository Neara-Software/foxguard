import * as vscode from "vscode";
import { execFile } from "child_process";
import * as path from "path";

/** Mirrors the JSON output of `foxguard --format json`. */
interface Finding {
  rule_id: string;
  severity: "low" | "medium" | "high" | "critical";
  cwe: string | null;
  description: string;
  file: string;
  line: number;
  column: number;
  end_line: number;
  end_column: number;
  snippet: string;
}

/** File extensions foxguard supports, mapped to language ids. */
const SUPPORTED_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".py",
  ".go",
  ".rb",
  ".java",
  ".php",
  ".rs",
  ".cs",
  ".swift",
]);

const SEVERITY_ORDER: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("foxguard");
  outputChannel = vscode.window.createOutputChannel("foxguard");

  context.subscriptions.push(diagnosticCollection, outputChannel);

  // Scan on save.
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      scanDocument(doc);
    })
  );

  // Manual scan command.
  context.subscriptions.push(
    vscode.commands.registerCommand("foxguard.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanDocument(editor.document);
      }
    })
  );

  // Clear diagnostics when a file is closed.
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      diagnosticCollection.delete(doc.uri);
    })
  );
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
}

// ---------------------------------------------------------------------------
// Core scanning logic
// ---------------------------------------------------------------------------

function isSupportedFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return SUPPORTED_EXTENSIONS.has(ext);
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function meetsMinSeverity(
  severity: string,
  minSeverity: string
): boolean {
  return (SEVERITY_ORDER[severity] ?? 0) >= (SEVERITY_ORDER[minSeverity] ?? 0);
}

async function resolveBinary(): Promise<string | null> {
  const config = vscode.workspace.getConfiguration("foxguard");
  const customPath = config.get<string>("path", "").trim();

  if (customPath) {
    return customPath;
  }

  // Check if foxguard is on PATH.
  const found = await new Promise<boolean>((resolve) => {
    execFile("foxguard", ["--version"], (err) => resolve(!err));
  });
  if (found) {
    return "foxguard";
  }

  // Try npx.
  const npxFound = await new Promise<boolean>((resolve) => {
    execFile("npx", ["foxguard", "--version"], (err) => resolve(!err));
  });
  if (npxFound) {
    return null; // sentinel: use npx wrapper
  }

  return undefined as unknown as null; // not found
}

function scanDocument(document: vscode.TextDocument): void {
  const filePath = document.uri.fsPath;

  if (!isSupportedFile(filePath)) {
    return;
  }

  const config = vscode.workspace.getConfiguration("foxguard");
  const minSeverity = config.get<string>("severity", "low");

  resolveBinary().then((binary) => {
    if (binary === (undefined as unknown as null)) {
      vscode.window
        .showInformationMessage(
          "foxguard is not installed. Install it with: npm install -g foxguard",
          "Install with npm"
        )
        .then((choice) => {
          if (choice) {
            const terminal = vscode.window.createTerminal("foxguard");
            terminal.show();
            terminal.sendText("npm install -g foxguard");
          }
        });
      return;
    }

    let command: string;
    let args: string[];

    if (binary === null) {
      // Use npx.
      command = "npx";
      args = ["foxguard", "--format", "json", filePath];
    } else {
      command = binary;
      args = ["--format", "json", filePath];
    }

    if (minSeverity && minSeverity !== "low") {
      args.splice(args.indexOf("--format"), 0, "--severity", minSeverity);
    }

    outputChannel.appendLine(`> ${command} ${args.join(" ")}`);

    execFile(
      command,
      args,
      { maxBuffer: 10 * 1024 * 1024, timeout: 30_000 },
      (error, stdout, stderr) => {
        if (stderr) {
          outputChannel.appendLine(stderr);
        }

        // foxguard exits non-zero when findings are present; that is normal.
        // A real failure usually means no JSON on stdout.
        if (!stdout.trim()) {
          diagnosticCollection.set(document.uri, []);
          return;
        }

        let findings: Finding[];
        try {
          findings = JSON.parse(stdout);
        } catch (e) {
          outputChannel.appendLine(`Failed to parse foxguard output: ${e}`);
          return;
        }

        const diagnostics: vscode.Diagnostic[] = findings
          .filter((f) => meetsMinSeverity(f.severity, minSeverity))
          .map((f) => {
            // foxguard uses 1-based lines/columns; VS Code uses 0-based.
            const range = new vscode.Range(
              Math.max(0, f.line - 1),
              Math.max(0, f.column - 1),
              Math.max(0, f.end_line - 1),
              Math.max(0, f.end_column - 1)
            );

            const cweTag = f.cwe ? ` [${f.cwe}]` : "";
            const message = `${f.description}${cweTag}`;

            const diag = new vscode.Diagnostic(
              range,
              message,
              mapSeverity(f.severity)
            );
            diag.source = "foxguard";
            diag.code = f.rule_id;
            return diag;
          });

        diagnosticCollection.set(document.uri, diagnostics);
        outputChannel.appendLine(
          `${filePath}: ${diagnostics.length} finding(s)`
        );
      }
    );
  });
}

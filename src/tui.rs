use crate::app::{execute_ui, DiffSummary, UiExecution, UiMode};
use crate::cli::UiArgs;
use crate::{Finding, Severity};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::{self, IsTerminal};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

pub fn run_scan_ui(args: &UiArgs) -> Result<i32, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("foxguard ui requires an interactive terminal".to_string());
    }

    let mut session = TerminalSession::enter()?;
    let (tx, rx) = mpsc::channel();
    let mut app = UiApp::new(args.clone());
    start_ui_execution(args.clone(), tx.clone());

    loop {
        app.handle_worker_messages(&rx);

        session
            .terminal
            .draw(|frame| app.draw(frame))
            .map_err(|e| e.to_string())?;

        if event::poll(Duration::from_millis(100)).map_err(|e| e.to_string())? {
            let Event::Key(key) = event::read().map_err(|e| e.to_string())? else {
                continue;
            };

            if key.kind != KeyEventKind::Press {
                continue;
            }

            match app.handle_key(key.code) {
                ControlFlow::Continue => {}
                ControlFlow::Rescan => start_ui_execution(app.request.clone(), tx.clone()),
                ControlFlow::Exit => break,
            }
        }

        if app.scanning {
            app.advance_spinner();
        }
    }

    if let Some(error) = app.error.take() {
        return Err(error);
    }

    let finding_count = app
        .result
        .as_ref()
        .map(|result| result.findings.len())
        .unwrap_or(0);
    Ok(if finding_count > 0 { 1 } else { 0 })
}

enum ControlFlow {
    Continue,
    Rescan,
    Exit,
}

struct UiApp {
    request: UiArgs,
    result: Option<UiExecution>,
    error: Option<String>,
    scanning: bool,
    spinner_index: usize,
    search_mode: bool,
    search_query: String,
    min_severity: Option<Severity>,
    selected: usize,
    show_trace: bool,
    show_notices: bool,
}

impl UiApp {
    fn new(request: UiArgs) -> Self {
        Self {
            show_trace: request.explain,
            request,
            result: None,
            error: None,
            scanning: true,
            spinner_index: 0,
            search_mode: false,
            search_query: String::new(),
            min_severity: None,
            selected: 0,
            show_notices: true,
        }
    }

    fn handle_worker_messages(&mut self, rx: &Receiver<Result<UiExecution, String>>) {
        while let Ok(message) = rx.try_recv() {
            self.scanning = false;
            match message {
                Ok(result) => {
                    self.show_trace = result.explain;
                    self.error = None;
                    self.result = Some(result);
                    self.clamp_selection();
                }
                Err(error) => {
                    self.result = None;
                    self.error = Some(error);
                }
            }
        }
    }

    fn handle_key(&mut self, key: KeyCode) -> ControlFlow {
        if self.search_mode {
            return self.handle_search_key(key);
        }

        match key {
            KeyCode::Char('q') => ControlFlow::Exit,
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_selection(1);
                ControlFlow::Continue
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_selection(-1);
                ControlFlow::Continue
            }
            KeyCode::Char('/') => {
                self.search_mode = true;
                ControlFlow::Continue
            }
            KeyCode::Char('0') => {
                self.min_severity = None;
                self.clamp_selection();
                ControlFlow::Continue
            }
            KeyCode::Char('1') => {
                self.min_severity = Some(Severity::Low);
                self.clamp_selection();
                ControlFlow::Continue
            }
            KeyCode::Char('2') => {
                self.min_severity = Some(Severity::Medium);
                self.clamp_selection();
                ControlFlow::Continue
            }
            KeyCode::Char('3') => {
                self.min_severity = Some(Severity::High);
                self.clamp_selection();
                ControlFlow::Continue
            }
            KeyCode::Char('4') => {
                self.min_severity = Some(Severity::Critical);
                self.clamp_selection();
                ControlFlow::Continue
            }
            KeyCode::Char('e') => {
                self.show_trace = !self.show_trace;
                ControlFlow::Continue
            }
            KeyCode::Char('w') => {
                self.show_notices = !self.show_notices;
                ControlFlow::Continue
            }
            KeyCode::Char('r') => {
                self.error = None;
                self.result = None;
                self.selected = 0;
                self.scanning = true;
                ControlFlow::Rescan
            }
            _ => ControlFlow::Continue,
        }
    }

    fn handle_search_key(&mut self, key: KeyCode) -> ControlFlow {
        match key {
            KeyCode::Esc => self.search_mode = false,
            KeyCode::Enter => {
                self.search_mode = false;
                self.clamp_selection();
            }
            KeyCode::Backspace => {
                self.search_query.pop();
                self.clamp_selection();
            }
            KeyCode::Char(ch) => {
                self.search_query.push(ch);
                self.clamp_selection();
            }
            _ => {}
        }

        ControlFlow::Continue
    }

    fn move_selection(&mut self, delta: isize) {
        let filtered = self.filtered_indices();
        if filtered.is_empty() {
            self.selected = 0;
            return;
        }

        let len = filtered.len() as isize;
        let next = (self.selected as isize + delta).clamp(0, len - 1);
        self.selected = next as usize;
    }

    fn clamp_selection(&mut self) {
        let filtered_len = self.filtered_indices().len();
        if filtered_len == 0 {
            self.selected = 0;
        } else if self.selected >= filtered_len {
            self.selected = filtered_len - 1;
        }
    }

    fn advance_spinner(&mut self) {
        self.spinner_index = (self.spinner_index + 1) % SPINNER_FRAMES.len();
    }

    fn filtered_indices(&self) -> Vec<usize> {
        let Some(result) = self.result.as_ref() else {
            return Vec::new();
        };

        let needle = self.search_query.to_ascii_lowercase();
        result
            .findings
            .iter()
            .enumerate()
            .filter(|(_, finding)| self.matches_filters(finding, &needle))
            .map(|(index, _)| index)
            .collect()
    }

    fn matches_filters(&self, finding: &Finding, needle: &str) -> bool {
        if let Some(min_severity) = self.min_severity {
            if finding.severity < min_severity {
                return false;
            }
        }

        if needle.is_empty() {
            return true;
        }

        [
            finding.rule_id.as_str(),
            finding.description.as_str(),
            finding.file.as_str(),
            finding.snippet.as_str(),
        ]
        .iter()
        .any(|value| value.to_ascii_lowercase().contains(needle))
    }

    fn selected_finding(&self) -> Option<&Finding> {
        let result = self.result.as_ref()?;
        let filtered = self.filtered_indices();
        let finding_index = *filtered.get(self.selected)?;
        result.findings.get(finding_index)
    }

    fn draw(&self, frame: &mut ratatui::Frame) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(frame.area());

        self.draw_header(frame, layout[0]);

        if self.scanning {
            self.draw_loading(frame, layout[1]);
        } else if let Some(error) = self.error.as_ref() {
            let error = Paragraph::new(error.as_str())
                .style(Style::default().fg(Color::Red))
                .block(Block::default().title("scan error").borders(Borders::ALL))
                .wrap(Wrap { trim: false });
            frame.render_widget(error, layout[1]);
        } else {
            self.draw_body(frame, layout[1]);
        }

        self.draw_footer(frame, layout[2]);
    }

    fn draw_loading(&self, frame: &mut ratatui::Frame, area: Rect) {
        let spinner = SPINNER_FRAMES[self.spinner_index];
        let loading = Paragraph::new(format!(
            "{} {} {}",
            spinner,
            request_mode_label(&self.request),
            self.request.path
        ))
        .block(Block::default().title("foxguard ui").borders(Borders::ALL));
        frame.render_widget(loading, area);
    }

    fn draw_header(&self, frame: &mut ratatui::Frame, area: Rect) {
        let mut spans = vec![
            Span::styled(
                "foxguard ui",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                request_mode_label(&self.request),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("  "),
            Span::raw(short_path(&self.request.path)),
        ];

        if let Some(result) = self.result.as_ref() {
            let counts = severity_counts(&result.findings);
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!(
                    "{} issues | {} files | {:.2}s",
                    result.findings.len(),
                    result.files_scanned,
                    result.duration.as_secs_f64()
                ),
                Style::default().fg(Color::Gray),
            ));
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!(
                    "C:{} H:{} M:{} L:{}",
                    counts.critical, counts.high, counts.medium, counts.low
                ),
                Style::default().fg(Color::Gray),
            ));

            if let Some(summary) = result.diff_summary.as_ref() {
                append_diff_summary(&mut spans, summary);
            }

            if result.files_scanned == 0 {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(
                    "no files found",
                    Style::default().fg(Color::Yellow),
                ));
            }
        }

        let header = Paragraph::new(Line::from(spans))
            .block(Block::default().borders(Borders::ALL).title("status"));
        frame.render_widget(header, area);
    }

    fn draw_body(&self, frame: &mut ratatui::Frame, area: Rect) {
        let body_layout = if self.show_notices && self.notice_count() > 0 {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(8), Constraint::Length(6)])
                .split(area)
        } else {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(8)])
                .split(area)
        };

        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(body_layout[0]);

        let filtered = self.filtered_indices();
        let items = if let Some(result) = self.result.as_ref() {
            filtered
                .iter()
                .map(|index| list_item(&result.findings[*index]))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        let list_title = self
            .result
            .as_ref()
            .map(|result| mode_findings_title(&result.mode))
            .unwrap_or("findings");
        let list = List::new(items)
            .block(Block::default().title(list_title).borders(Borders::ALL))
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol(">> ");

        let mut state = ListState::default();
        if !filtered.is_empty() {
            state.select(Some(self.selected));
        }
        frame.render_stateful_widget(list, layout[0], &mut state);

        let detail = Paragraph::new(self.detail_text())
            .block(Block::default().title("detail").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(detail, layout[1]);

        if body_layout.len() > 1 {
            let notices = Paragraph::new(self.notice_text())
                .block(Block::default().title("notices").borders(Borders::ALL))
                .wrap(Wrap { trim: false });
            frame.render_widget(notices, body_layout[1]);
        }
    }

    fn detail_text(&self) -> Text<'static> {
        let Some(finding) = self.selected_finding() else {
            if self.result.is_some() {
                return Text::from("No findings match the current filters.");
            }
            return Text::from("");
        };

        let mut lines = vec![
            Line::from(vec![
                Span::styled(
                    severity_label(finding.severity),
                    severity_style(finding.severity),
                ),
                Span::raw("  "),
                Span::styled(
                    finding.rule_id.clone(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(finding.description.clone()),
            Line::from(format!(
                "{}:{}:{}",
                short_path(&finding.file),
                finding.line,
                finding.column
            )),
        ];

        if let Some(cwe) = finding.cwe.as_ref() {
            lines.push(Line::from(format!("CWE: {}", cwe)));
        }

        lines.push(Line::from(""));
        lines.push(section_heading("Snippet", Color::Yellow));
        for line in finding.snippet.lines() {
            lines.push(Line::from(line.to_string()));
        }

        if self.show_trace {
            if let (Some(line), Some(description)) =
                (finding.source_line, finding.source_description.as_ref())
            {
                lines.push(Line::from(""));
                lines.push(section_heading("Source", Color::Yellow));
                lines.push(Line::from(format!("line {}: {}", line, description)));
            }

            if let (Some(line), Some(description)) =
                (finding.sink_line, finding.sink_description.as_ref())
            {
                lines.push(Line::from(""));
                lines.push(section_heading("Sink", Color::Red));
                lines.push(Line::from(format!("line {}: {}", line, description)));
            }
        }

        if let Some(fix) = finding.fix_suggestion.as_ref() {
            lines.push(Line::from(""));
            lines.push(section_heading("Fix", Color::Green));
            lines.push(Line::from(fix.clone()));
        }

        Text::from(lines)
    }

    fn draw_footer(&self, frame: &mut ratatui::Frame, area: Rect) {
        let filter = self
            .min_severity
            .map(severity_name)
            .unwrap_or("all severities");
        let mode_label = if self.search_mode { "/" } else { "" };
        let notices = self.notice_count();
        let footer = Paragraph::new(format!(
            "mode: {}  j/k move  / search  0-4 severity  e trace  w notices({})  r rescan  q quit  filter: {}  search: {}{}",
            request_mode_label(&self.request),
            notices,
            filter,
            mode_label,
            self.search_query
        ))
        .block(Block::default().borders(Borders::ALL).title("keys"))
        .wrap(Wrap { trim: true });
        frame.render_widget(footer, area);
    }

    fn notice_count(&self) -> usize {
        self.result
            .as_ref()
            .map(|result| result.notices.len())
            .unwrap_or(0)
    }

    fn notice_text(&self) -> Text<'static> {
        let Some(result) = self.result.as_ref() else {
            return Text::from("");
        };

        if result.notices.is_empty() {
            return Text::from("No notices.");
        }

        let lines = result
            .notices
            .iter()
            .map(|notice| Line::from(notice.clone()))
            .collect::<Vec<_>>();
        Text::from(lines)
    }
}

struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalSession {
    fn enter() -> Result<Self, String> {
        enable_raw_mode().map_err(|e| e.to_string())?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen).map_err(|e| e.to_string())?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).map_err(|e| e.to_string())?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

fn start_ui_execution(args: UiArgs, tx: Sender<Result<UiExecution, String>>) {
    std::thread::spawn(move || {
        let _ = tx.send(execute_ui(&args));
    });
}

fn append_diff_summary(spans: &mut Vec<Span<'static>>, summary: &DiffSummary) {
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        format!(
            "vs {} | {} new | {} total | {} existing",
            summary.target,
            summary.total_current.saturating_sub(summary.existing_count),
            summary.total_current,
            summary.existing_count
        ),
        Style::default().fg(Color::Gray),
    ));
}

fn list_item(finding: &Finding) -> ListItem<'static> {
    let line = Line::from(vec![
        Span::styled(
            severity_label(finding.severity),
            severity_style(finding.severity),
        ),
        Span::raw(" "),
        Span::styled(
            finding.rule_id.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{}:{}", short_path(&finding.file), finding.line),
            Style::default().fg(Color::Gray),
        ),
    ]);
    ListItem::new(line)
}

fn severity_counts(findings: &[Finding]) -> SeverityCounts {
    let mut counts = SeverityCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };

    for finding in findings {
        match finding.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
        }
    }

    counts
}

fn section_heading(label: &str, color: Color) -> Line<'static> {
    Line::from(Span::styled(
        label.to_string(),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    ))
}

fn mode_findings_title(mode: &UiMode) -> &'static str {
    match mode {
        UiMode::Scan => "findings",
        UiMode::Diff { .. } => "new findings",
        UiMode::Secrets => "secrets",
    }
}

fn request_mode_label(args: &UiArgs) -> &'static str {
    if args.secrets {
        "secrets"
    } else if args.diff.is_some() {
        "diff"
    } else {
        "scan"
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED ",
        Severity::Low => "LOW ",
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical+",
        Severity::High => "high+",
        Severity::Medium => "medium+",
        Severity::Low => "low+",
    }
}

fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD),
        Severity::High => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::Medium => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        Severity::Low => Style::default()
            .fg(Color::Blue)
            .add_modifier(Modifier::BOLD),
    }
}

fn short_path(path: &str) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(relative) = Path::new(path).strip_prefix(&cwd) {
            return relative.display().to_string();
        }
    }

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 4 {
        format!(".../{}", parts[parts.len() - 3..].join("/"))
    } else {
        path.to_string()
    }
}

const SPINNER_FRAMES: &[&str] = &["-", "\\", "|", "/"];

use crate::app::{execute_ui, DiffSummary, UiExecution, UiMode};
use crate::cli::UiArgs;
use crate::{Finding, Severity};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

pub fn run_scan_ui(args: &UiArgs) -> Result<i32, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("foxguard ui requires an interactive terminal".to_string());
    }

    let mut session = TerminalSession::enter()?;
    let (tx, rx) = mpsc::channel();
    let mut app = UiApp::new(args.clone());
    start_ui_execution(app.begin_scan(), args.clone(), tx.clone());

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

            match app.handle_key(key) {
                ControlFlow::Continue => {}
                ControlFlow::Rescan => {
                    let request_id = app.begin_scan();
                    start_ui_execution(request_id, app.request.clone(), tx.clone())
                }
                ControlFlow::OpenSelected => {
                    if let Err(error) = app.open_selected_finding(&mut session) {
                        app.push_runtime_notice(format!("open failed: {}", error));
                    }
                }
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
    OpenSelected,
    Exit,
}

struct WorkerMessage {
    request_id: u64,
    result: Result<UiExecution, String>,
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
    show_help: bool,
    runtime_notices: Vec<String>,
    active_request_id: u64,
    next_request_id: u64,
    scan_started_at: Instant,
    detail_scroll: u16,
    notices_scroll: u16,
    source_context_cache: Option<SourceContextCache>,
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
            show_help: false,
            runtime_notices: Vec::new(),
            active_request_id: 0,
            next_request_id: 1,
            scan_started_at: Instant::now(),
            detail_scroll: 0,
            notices_scroll: 0,
            source_context_cache: None,
        }
    }

    fn begin_scan(&mut self) -> u64 {
        self.error = None;
        self.result = None;
        self.selected = 0;
        self.scanning = true;
        self.show_help = false;
        self.runtime_notices.clear();
        self.scan_started_at = Instant::now();
        self.detail_scroll = 0;
        self.notices_scroll = 0;
        self.source_context_cache = None;
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        self.active_request_id = request_id;
        request_id
    }

    fn handle_worker_messages(&mut self, rx: &Receiver<WorkerMessage>) {
        while let Ok(message) = rx.try_recv() {
            if message.request_id != self.active_request_id {
                continue;
            }

            self.scanning = false;
            match message.result {
                Ok(result) => {
                    self.show_trace = result.explain;
                    self.error = None;
                    self.result = Some(result);
                    self.source_context_cache = None;
                    self.clamp_selection();
                }
                Err(error) => {
                    self.result = None;
                    self.error = Some(error);
                }
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> ControlFlow {
        if matches!(key.code, KeyCode::Char('?')) {
            self.show_help = !self.show_help;
            return ControlFlow::Continue;
        }

        if self.show_help {
            return match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.show_help = false;
                    ControlFlow::Continue
                }
                _ => ControlFlow::Continue,
            };
        }

        if self.search_mode {
            return self.handle_search_key(key.code);
        }

        match key.code {
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
                self.detail_scroll = 0;
                ControlFlow::Continue
            }
            KeyCode::Char('w') => {
                self.show_notices = !self.show_notices;
                ControlFlow::Continue
            }
            KeyCode::PageDown => {
                self.scroll_detail(8);
                ControlFlow::Continue
            }
            KeyCode::PageUp => {
                self.scroll_detail(-8);
                ControlFlow::Continue
            }
            KeyCode::Char(']') => {
                self.scroll_notices(3);
                ControlFlow::Continue
            }
            KeyCode::Char('[') => {
                self.scroll_notices(-3);
                ControlFlow::Continue
            }
            KeyCode::Enter => ControlFlow::OpenSelected,
            KeyCode::Char('o') => ControlFlow::OpenSelected,
            KeyCode::Char('r') => ControlFlow::Rescan,
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
        let previous = self.selected;
        if filtered.is_empty() {
            self.selected = 0;
            return;
        }

        let len = filtered.len() as isize;
        let next = (self.selected as isize + delta).clamp(0, len - 1);
        self.selected = next as usize;
        if self.selected != previous {
            self.detail_scroll = 0;
            self.source_context_cache = None;
        }
    }

    fn clamp_selection(&mut self) {
        let previous = self.selected;
        let filtered_len = self.filtered_indices().len();
        if filtered_len == 0 {
            self.selected = 0;
        } else if self.selected >= filtered_len {
            self.selected = filtered_len - 1;
        }

        if self.selected != previous {
            self.detail_scroll = 0;
            self.source_context_cache = None;
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
        let mut indices = result
            .findings
            .iter()
            .enumerate()
            .filter(|(_, finding)| self.matches_filters(finding, &needle))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        indices.sort_by(|left, right| {
            compare_findings(&result.findings[*left], &result.findings[*right])
        });

        indices
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

    fn draw(&mut self, frame: &mut ratatui::Frame) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
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

        if self.show_help {
            self.draw_help(frame);
        }
    }

    fn draw_loading(&self, frame: &mut ratatui::Frame, area: Rect) {
        let spinner = SPINNER_FRAMES[self.spinner_index];
        let elapsed = self.scan_started_at.elapsed().as_secs_f32();
        let loading = Paragraph::new(format!(
            "{} {} {}\n\nelapsed: {:.1}s\nwaiting for scan results...",
            spinner,
            request_mode_label(&self.request),
            self.request.path,
            elapsed,
        ))
        .block(Block::default().title("foxguard ui").borders(Borders::ALL));
        frame.render_widget(loading, area);
    }

    fn draw_header(&self, frame: &mut ratatui::Frame, area: Rect) {
        let mut summary_spans = vec![
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

        let mut badge_spans = Vec::new();

        if let Some(result) = self.result.as_ref() {
            let counts = severity_counts(&result.findings);
            summary_spans.push(Span::raw("  "));
            summary_spans.push(Span::styled(
                format!(
                    "{} issues | {} files | {:.2}s",
                    result.findings.len(),
                    result.files_scanned,
                    result.duration.as_secs_f64()
                ),
                Style::default().fg(Color::Gray),
            ));
            badge_spans = severity_badge_spans(&counts);

            if let Some(summary) = result.diff_summary.as_ref() {
                append_diff_summary(&mut summary_spans, summary);
            }

            if result.files_scanned == 0 {
                summary_spans.push(Span::raw("  "));
                summary_spans.push(Span::styled(
                    "no files found",
                    Style::default().fg(Color::Yellow),
                ));
            }
        } else if self.scanning {
            summary_spans.push(Span::raw("  "));
            summary_spans.push(Span::styled(
                format!(
                    "elapsed {:.1}s",
                    self.scan_started_at.elapsed().as_secs_f32()
                ),
                Style::default().fg(Color::Gray),
            ));
        }

        let mut lines = vec![Line::from(summary_spans)];
        if !badge_spans.is_empty() {
            lines.push(Line::from(badge_spans));
        }

        let header = Paragraph::new(Text::from(lines))
            .block(Block::default().borders(Borders::ALL).title("status"));
        frame.render_widget(header, area);
    }

    fn draw_body(&mut self, frame: &mut ratatui::Frame, area: Rect) {
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

        let direction = if body_layout[0].width < 110 {
            Direction::Vertical
        } else {
            Direction::Horizontal
        };
        let constraints = if matches!(direction, Direction::Vertical) {
            vec![Constraint::Percentage(45), Constraint::Percentage(55)]
        } else {
            vec![Constraint::Percentage(42), Constraint::Percentage(58)]
        };
        let layout = Layout::default()
            .direction(direction)
            .constraints(constraints)
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
            .map(|result| {
                format!(
                    "{} ({}/{})",
                    mode_findings_title(&result.mode),
                    if filtered.is_empty() {
                        0
                    } else {
                        self.selected + 1
                    },
                    filtered.len()
                )
            })
            .unwrap_or_else(|| "findings".to_string());
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
            .scroll((self.detail_scroll, 0))
            .wrap(Wrap { trim: false });
        frame.render_widget(detail, layout[1]);

        if body_layout.len() > 1 {
            let notices = Paragraph::new(self.notice_text())
                .block(Block::default().title("notices").borders(Borders::ALL))
                .scroll((self.notices_scroll, 0))
                .wrap(Wrap { trim: false });
            frame.render_widget(notices, body_layout[1]);
        }
    }

    fn detail_text(&mut self) -> Text<'static> {
        let Some(finding) = self.selected_finding().cloned() else {
            if self.result.is_some() {
                return Text::from("No findings match the current filters.");
            }
            return Text::from("");
        };

        let mut lines = vec![
            Line::from(vec![
                severity_badge_span(finding.severity),
                Span::raw("  "),
                Span::styled(
                    finding.description.clone(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            metadata_line("Rule", &finding.rule_id),
            metadata_line(
                "Location",
                &format!(
                    "{}:{}:{}",
                    short_path(&finding.file),
                    finding.line,
                    finding.column
                ),
            ),
        ];

        if let Some(cwe) = finding.cwe.as_ref() {
            lines.push(metadata_line("CWE", cwe));
        }

        if let Some(context_lines) = self.source_context_lines(&finding) {
            lines.push(Line::from(""));
            lines.push(section_heading("Context", Color::Yellow));
            lines.extend(context_lines);
        }

        lines.push(Line::from(""));
        lines.push(section_heading("Snippet", Color::Yellow));
        for line in finding.snippet.lines() {
            lines.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::Gray),
            )));
        }

        if self.show_trace {
            lines.push(Line::from(""));
            lines.push(section_heading("Dataflow", Color::Cyan));
            lines.extend(dataflow_lines(&finding));
        }

        if let Some(fix) = finding.fix_suggestion.as_ref() {
            lines.push(Line::from(""));
            lines.push(section_heading("Fix", Color::Green));
            lines.push(Line::from(fix.clone()));
        }

        Text::from(lines)
    }

    fn source_context_lines(&mut self, finding: &Finding) -> Option<Vec<Line<'static>>> {
        if self.request.secrets {
            return None;
        }

        let path = resolve_finding_path(&self.request.path, &finding.file);
        let key = SourceContextCacheKey {
            path,
            line: finding.line,
            end_line: finding.end_line,
            column: finding.column,
            end_column: finding.end_column,
        };

        if let Some(cache) = self.source_context_cache.as_ref() {
            if cache.key == key {
                return Some(cache.lines.clone());
            }
        }

        let lines = match fs::read_to_string(&key.path) {
            Ok(source) => render_source_context(&source, finding, 2),
            Err(error) => vec![Line::from(Span::styled(
                format!("Unable to load source context: {}", error),
                Style::default().fg(Color::DarkGray),
            ))],
        };

        self.source_context_cache = Some(SourceContextCache {
            key,
            lines: lines.clone(),
        });

        Some(lines)
    }

    fn draw_footer(&self, frame: &mut ratatui::Frame, area: Rect) {
        let filter = self
            .min_severity
            .map(severity_name)
            .unwrap_or("all severities");
        let mode_label = if self.search_mode { "/" } else { "" };
        let notices = self.notice_count();
        let footer = Paragraph::new(format!(
            "mode: {}  j/k move  / search  Enter/o open  e flow  ? help  notices:{}  filter: {}  search: {}{}",
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

    fn draw_help(&self, frame: &mut ratatui::Frame) {
        let area = centered_rect(56, 42, frame.area());
        frame.render_widget(Clear, area);
        let help = Paragraph::new(Text::from(vec![
            Line::from(Span::styled(
                "foxguard ui help",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("j/k or arrows  move between findings"),
            Line::from("/              search findings"),
            Line::from("0-4            set minimum severity filter"),
            Line::from("e              toggle dataflow details (source/sink traces)"),
            Line::from("Enter or o     open the selected finding in your editor"),
            Line::from("w              show or hide notices panel"),
            Line::from("PageUp/Down    scroll detail pane"),
            Line::from("[/]            scroll notices pane"),
            Line::from("r              rescan"),
            Line::from("q              quit"),
            Line::from("? or Esc       close this help"),
        ]))
        .alignment(Alignment::Left)
        .style(Style::default().bg(Color::Rgb(22, 24, 29)).fg(Color::White))
        .block(
            Block::default()
                .title("help")
                .borders(Borders::ALL)
                .style(Style::default().bg(Color::Rgb(22, 24, 29))),
        )
        .wrap(Wrap { trim: false });
        frame.render_widget(help, area);
    }

    fn open_selected_finding(&mut self, session: &mut TerminalSession) -> Result<(), String> {
        let target = self
            .selected_finding()
            .map(|finding| OpenTarget {
                path: resolve_finding_path(&self.request.path, &finding.file),
                line: finding.line.max(1),
            })
            .ok_or_else(|| "no finding selected".to_string())?;

        if !target.path.exists() {
            return Err(format!("{} does not exist", target.path.display()));
        }

        let command_spec = open_command_spec(&target)?;
        session.suspend()?;
        let status = Command::new(&command_spec.program)
            .args(&command_spec.args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| format!("failed to launch {}: {}", command_spec.program, e));
        session.resume()?;

        match status {
            Ok(exit) if exit.success() => {
                self.push_runtime_notice(format!(
                    "opened {}:{}",
                    target.path.display(),
                    target.line
                ));
                Ok(())
            }
            Ok(exit) => Err(format!(
                "{} exited with status {}",
                command_spec.program, exit
            )),
            Err(error) => Err(error),
        }
    }

    fn push_runtime_notice(&mut self, notice: String) {
        self.runtime_notices.push(notice);
    }

    fn scroll_detail(&mut self, delta: i32) {
        self.detail_scroll = adjust_scroll(self.detail_scroll, delta);
    }

    fn scroll_notices(&mut self, delta: i32) {
        self.notices_scroll = adjust_scroll(self.notices_scroll, delta);
    }

    fn notice_count(&self) -> usize {
        self.combined_notices().len()
    }

    fn notice_text(&self) -> Text<'static> {
        let notices = self.combined_notices();
        if notices.is_empty() {
            return Text::from("No notices.");
        }

        let lines = notices
            .iter()
            .map(|notice| Line::from(notice.clone()))
            .collect::<Vec<_>>();
        Text::from(lines)
    }

    fn combined_notices(&self) -> Vec<String> {
        let mut notices = self
            .result
            .as_ref()
            .map(|result| result.notices.clone())
            .unwrap_or_default();
        notices.extend(self.runtime_notices.iter().cloned());
        notices
    }
}

struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

#[derive(Clone, PartialEq, Eq)]
struct SourceContextCacheKey {
    path: PathBuf,
    line: usize,
    end_line: usize,
    column: usize,
    end_column: usize,
}

struct SourceContextCache {
    key: SourceContextCacheKey,
    lines: Vec<Line<'static>>,
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    active: bool,
}

impl TerminalSession {
    fn enter() -> Result<Self, String> {
        enable_raw_mode().map_err(|e| e.to_string())?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen).map_err(|e| e.to_string())?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).map_err(|e| e.to_string())?;
        Ok(Self {
            terminal,
            active: true,
        })
    }

    fn suspend(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }

        disable_raw_mode().map_err(|e| e.to_string())?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen).map_err(|e| e.to_string())?;
        self.terminal.show_cursor().map_err(|e| e.to_string())?;
        self.active = false;
        Ok(())
    }

    fn resume(&mut self) -> Result<(), String> {
        if self.active {
            return Ok(());
        }

        enable_raw_mode().map_err(|e| e.to_string())?;
        execute!(self.terminal.backend_mut(), EnterAlternateScreen).map_err(|e| e.to_string())?;
        self.terminal.clear().map_err(|e| e.to_string())?;
        self.active = true;
        Ok(())
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

fn start_ui_execution(request_id: u64, args: UiArgs, tx: Sender<WorkerMessage>) {
    std::thread::spawn(move || {
        let _ = tx.send(WorkerMessage {
            request_id,
            result: execute_ui(&args),
        });
    });
}

struct OpenTarget {
    path: PathBuf,
    line: usize,
}

struct CommandSpec {
    program: String,
    args: Vec<String>,
}

fn open_command_spec(target: &OpenTarget) -> Result<CommandSpec, String> {
    open_command_spec_from_editor(
        target,
        std::env::var_os("EDITOR")
            .as_ref()
            .map(|editor| editor.to_string_lossy().into_owned()),
    )
}

fn open_command_spec_from_editor(
    target: &OpenTarget,
    editor: Option<String>,
) -> Result<CommandSpec, String> {
    if let Some(editor) = editor {
        let mut parts = editor
            .split_whitespace()
            .map(|part| part.to_string())
            .collect::<Vec<_>>();
        if parts.is_empty() {
            return Err("$EDITOR is set but empty".to_string());
        }

        let program = parts.remove(0);
        let basename = Path::new(&program)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(program.as_str());
        let mut args = parts;

        match basename {
            "code" | "code-insiders" | "cursor" | "codium" | "windsurf" => {
                args.push("-g".to_string());
                args.push(format!("{}:{}", target.path.display(), target.line));
            }
            "hx" | "helix" => {
                args.push(format!("{}:{}", target.path.display(), target.line));
            }
            "vim" | "nvim" | "vi" | "nano" | "emacs" => {
                args.push(format!("+{}", target.line));
                args.push(target.path.display().to_string());
            }
            _ => {
                args.push(target.path.display().to_string());
            }
        }

        return Ok(CommandSpec { program, args });
    }

    if cfg!(target_os = "macos") {
        return Ok(CommandSpec {
            program: "open".to_string(),
            args: vec![target.path.display().to_string()],
        });
    }

    if cfg!(target_os = "windows") {
        return Ok(CommandSpec {
            program: "cmd".to_string(),
            args: vec![
                "/C".to_string(),
                "start".to_string(),
                String::new(),
                target.path.display().to_string(),
            ],
        });
    }

    Ok(CommandSpec {
        program: "xdg-open".to_string(),
        args: vec![target.path.display().to_string()],
    })
}

fn resolve_finding_path(scan_path: &str, finding_file: &str) -> PathBuf {
    let finding_path = Path::new(finding_file);
    if finding_path.is_absolute() {
        return finding_path.to_path_buf();
    }

    let scan_root = Path::new(scan_path);
    let scan_root_is_file = scan_root.is_file() || scan_root.extension().is_some();
    let base = if scan_root_is_file {
        scan_root.parent().unwrap_or_else(|| Path::new("."))
    } else {
        scan_root
    };

    base.join(finding_path)
}

#[cfg(test)]
fn truncate_text(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{}...", truncated)
    } else {
        truncated
    }
}

fn adjust_scroll(current: u16, delta: i32) -> u16 {
    if delta.is_negative() {
        current.saturating_sub(delta.unsigned_abs() as u16)
    } else {
        current.saturating_add(delta as u16)
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_finding_path_joins_relative_file_under_directory_root() {
        let resolved = resolve_finding_path("/tmp/project", "src/main.rs");
        assert_eq!(resolved, PathBuf::from("/tmp/project/src/main.rs"));
    }

    #[test]
    fn resolve_finding_path_uses_parent_for_file_roots() {
        let resolved = resolve_finding_path("/tmp/project/app.py", "app.py");
        assert_eq!(resolved, PathBuf::from("/tmp/project/app.py"));
    }

    #[test]
    fn open_command_spec_uses_code_goto_format() {
        let target = OpenTarget {
            path: PathBuf::from("/tmp/project/src/main.rs"),
            line: 27,
        };

        let command = open_command_spec_from_editor(&target, Some("code --wait".to_string()))
            .expect("command should build");

        assert_eq!(command.program, "code");
        assert_eq!(
            command.args,
            vec![
                "--wait".to_string(),
                "-g".to_string(),
                "/tmp/project/src/main.rs:27".to_string()
            ]
        );
    }

    #[test]
    fn open_command_spec_uses_vim_line_format() {
        let target = OpenTarget {
            path: PathBuf::from("/tmp/project/src/main.rs"),
            line: 8,
        };

        let command = open_command_spec_from_editor(&target, Some("nvim".to_string()))
            .expect("command should build");

        assert_eq!(command.program, "nvim");
        assert_eq!(
            command.args,
            vec!["+8".to_string(), "/tmp/project/src/main.rs".to_string()]
        );
    }

    #[test]
    fn begin_scan_resets_runtime_notices_and_updates_request_id() {
        let mut app = UiApp::new(UiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
        });
        app.runtime_notices.push("stale notice".to_string());

        let first = app.begin_scan();
        let second = app.begin_scan();

        assert_eq!(first, 1);
        assert_eq!(second, 2);
        assert!(app.runtime_notices.is_empty());
        assert_eq!(app.active_request_id, 2);
    }

    #[test]
    fn compare_findings_prioritizes_higher_severity() {
        let critical = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::Critical,
            file: "a.js".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 5,
            description: "critical".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
        };
        let medium = Finding {
            severity: Severity::Medium,
            ..critical.clone()
        };

        assert_eq!(
            compare_findings(&critical, &medium),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn truncate_text_adds_ellipsis_when_needed() {
        assert_eq!(truncate_text("abcdef", 3), "abc...");
        assert_eq!(truncate_text("abc", 3), "abc");
    }

    #[test]
    fn dataflow_lines_render_path_when_source_and_sink_are_present() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "/tmp/project/src/main.js".to_string(),
            line: 42,
            column: 7,
            end_line: 42,
            end_column: 18,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: Some(12),
            source_description: Some("user-controlled query param".to_string()),
            sink_line: Some(42),
            sink_description: Some("value is passed into exec".to_string()),
            fix_suggestion: None,
        };

        let rendered = dataflow_lines(&finding)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();

        assert!(rendered
            .iter()
            .any(|line| line.contains("+- source @ line 12")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("+- finding @ .../project/src/main.js:42:7")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("`- sink @ line 42")));
    }

    #[test]
    fn dataflow_lines_show_fallback_when_no_trace_exists() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 42,
            column: 7,
            end_line: 42,
            end_column: 18,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
        };

        assert_eq!(
            dataflow_lines(&finding)
                .into_iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>(),
            vec!["No source/sink flow details for this finding type.".to_string()]
        );
    }

    #[test]
    fn render_source_context_includes_surrounding_lines_and_caret() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 3,
            column: 6,
            end_line: 3,
            end_column: 9,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
        };

        let rendered = render_source_context(
            "const user = req.query.user;\nconst cmd = user;\nexec(cmd);\nconsole.log(cmd);\n",
            &finding,
            1,
        )
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

        assert!(rendered
            .iter()
            .any(|line| line.contains("2 | const cmd = user;")));
        assert!(rendered.iter().any(|line| {
            line.contains("exec(cmd);") && line.contains("|") && line.contains(">")
        }));
        assert!(rendered.iter().any(|line| line.contains("^")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("4 | console.log(cmd);")));
    }

    #[test]
    fn handle_key_maps_enter_to_open_selected() {
        let mut app = UiApp::new(UiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
        });

        let flow = app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(flow, ControlFlow::OpenSelected));
    }

    #[test]
    fn render_source_context_marks_each_line_of_multiline_findings() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 2,
            column: 7,
            end_line: 4,
            end_column: 5,
            description: "multiline finding".to_string(),
            snippet: "foo(\n  bar,\n  baz\n)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
        };

        let rendered = render_source_context(
            "const x = 1;\ncall(foo,\n  bar,\n  baz);\nconst y = 2;\n",
            &finding,
            0,
        )
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

        assert!(rendered
            .iter()
            .any(|line| line.contains("call(foo,") && line.contains(">") && line.contains("|")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("bar,") && line.contains(">") && line.contains("|")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("baz);") && line.contains(">") && line.contains("|")));
        assert!(
            rendered
                .iter()
                .filter(|line| line.contains("selected range"))
                .count()
                >= 3
        );
    }

    #[test]
    fn render_source_context_truncates_long_lines_around_selected_range() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 1,
            column: 90,
            end_line: 1,
            end_column: 105,
            description: "long line finding".to_string(),
            snippet: "dangerous_call(user_input)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
        };

        let rendered = render_source_context(
            "prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_dangerous_call(user_input)_suffix_suffix_suffix_suffix_suffix\n",
            &finding,
            0,
        )
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

        assert!(rendered.iter().any(|line| line.contains("...")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("dangerous_call(user_input)")));
    }
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
    ListItem::new(vec![
        Line::from(vec![
            severity_badge_span(finding.severity),
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
        ]),
        Line::from(""),
    ])
}

fn dataflow_lines(finding: &Finding) -> Vec<Line<'static>> {
    let mut steps = Vec::new();

    if let (Some(line), Some(description)) =
        (finding.source_line, finding.source_description.as_ref())
    {
        steps.push((
            "source",
            format!("line {}", line),
            Some(description.clone()),
            Color::Yellow,
        ));
    }

    if finding.source_line.is_none() && finding.sink_line.is_none() {
        return vec![Line::from(
            "No source/sink flow details for this finding type.",
        )];
    }

    steps.push((
        "finding",
        format!(
            "{}:{}:{}",
            short_path(&finding.file),
            finding.line,
            finding.column
        ),
        None,
        flow_accent_color(finding.severity),
    ));

    if let (Some(line), Some(description)) = (finding.sink_line, finding.sink_description.as_ref())
    {
        steps.push((
            "sink",
            format!("line {}", line),
            Some(description.clone()),
            Color::Red,
        ));
    }

    let mut lines = Vec::new();
    let step_count = steps.len();
    for (index, (label, location, description, color)) in steps.into_iter().enumerate() {
        let is_last = index + 1 == step_count;
        let branch = if is_last { "`- " } else { "+- " };
        let stem = if is_last { "   " } else { "|  " };

        lines.push(Line::from(vec![
            Span::styled(branch, Style::default().fg(Color::DarkGray)),
            Span::styled(
                label.to_string(),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" @ {}", location), Style::default().fg(Color::Gray)),
        ]));

        if let Some(description) = description {
            for detail_line in description.lines() {
                lines.push(Line::from(vec![
                    Span::styled(stem, Style::default().fg(Color::DarkGray)),
                    Span::raw(detail_line.to_string()),
                ]));
            }
        }

        if !is_last {
            lines.push(Line::from(Span::styled(
                "|",
                Style::default().fg(Color::DarkGray),
            )));
        }
    }

    lines
}

fn render_source_context(source: &str, finding: &Finding, radius: usize) -> Vec<Line<'static>> {
    let source_lines = source.lines().collect::<Vec<_>>();
    if source_lines.is_empty() {
        return vec![Line::from(Span::styled(
            "Source file is empty.",
            Style::default().fg(Color::DarkGray),
        ))];
    }

    let highlighted_end = finding.end_line.max(finding.line).min(source_lines.len());
    let start_line = finding.line.saturating_sub(radius).max(1);
    let end_line = highlighted_end
        .saturating_add(radius)
        .min(source_lines.len());
    let width = end_line.to_string().len().max(2);
    let accent = flow_accent_color(finding.severity);
    let mut lines = Vec::new();

    for number in start_line..=end_line {
        let is_highlighted = (finding.line..=highlighted_end).contains(&number);
        let rendered = render_context_line(source_lines[number - 1], finding, number);
        let marker = if is_highlighted { "> " } else { "  " };
        let text_style = if is_highlighted {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        lines.push(Line::from(vec![
            Span::styled(
                marker,
                Style::default().fg(accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{:>width$} ", number, width = width),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("| ", Style::default().fg(Color::DarkGray)),
            Span::styled(rendered.text, text_style),
        ]));

        if let Some((offset, width)) = rendered.highlight {
            lines.push(context_caret_line(width, offset, width, accent));
        }
    }

    lines
}

fn render_context_line(line: &str, finding: &Finding, line_number: usize) -> RenderedContextLine {
    let chars = line.chars().collect::<Vec<_>>();
    let char_len = chars.len();
    let highlight = highlight_range_for_line(finding, line_number, char_len);
    let mut window_start = 0;

    if char_len > CONTEXT_LINE_MAX_CHARS {
        if let Some((start, _)) = highlight {
            let focus = start.saturating_sub(1);
            window_start = focus.saturating_sub(CONTEXT_FOCUS_LEAD);
        }
        window_start = window_start.min(char_len.saturating_sub(CONTEXT_LINE_MAX_CHARS));
    }

    let window_end = (window_start + CONTEXT_LINE_MAX_CHARS).min(char_len);
    let leading_ellipsis = window_start > 0;
    let trailing_ellipsis = window_end < char_len;
    let mut text = String::new();
    if leading_ellipsis {
        text.push_str("...");
    }
    text.push_str(&chars[window_start..window_end].iter().collect::<String>());
    if trailing_ellipsis {
        text.push_str("...");
    }

    let visible_highlight = highlight.and_then(|(start, end)| {
        let visible_start = start.max(window_start + 1);
        let visible_end = end.min(window_end + 1);
        if visible_start >= visible_end {
            return None;
        }

        let ellipsis_offset = if leading_ellipsis { 3 } else { 0 };
        Some((
            ellipsis_offset + visible_start.saturating_sub(window_start + 1),
            visible_end.saturating_sub(visible_start),
        ))
    });

    RenderedContextLine {
        text,
        highlight: visible_highlight,
    }
}

fn highlight_range_for_line(
    finding: &Finding,
    line_number: usize,
    line_char_len: usize,
) -> Option<(usize, usize)> {
    if line_number < finding.line || line_number > finding.end_line {
        return None;
    }

    let start = if line_number == finding.line {
        finding.column.max(1)
    } else {
        1
    };
    let end = if line_number == finding.end_line {
        finding.end_column.max(start + 1)
    } else {
        line_char_len + 1
    };

    Some((
        start.min(line_char_len + 1),
        end.min(line_char_len + 1).max(start + 1),
    ))
}

fn context_caret_line(
    line_number_width: usize,
    caret_offset: usize,
    caret_width: usize,
    accent: Color,
) -> Line<'static> {
    let caret_width = caret_width.max(1);

    Line::from(vec![
        Span::raw("  "),
        Span::raw(" ".repeat(line_number_width + 1)),
        Span::styled("| ", Style::default().fg(Color::DarkGray)),
        Span::raw(" ".repeat(caret_offset)),
        Span::styled(
            "^".repeat(caret_width),
            Style::default().fg(accent).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" selected range", Style::default().fg(Color::DarkGray)),
    ])
}

struct RenderedContextLine {
    text: String,
    highlight: Option<(usize, usize)>,
}

fn compare_findings(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    severity_rank(right.severity)
        .cmp(&severity_rank(left.severity))
        .then(left.file.cmp(&right.file))
        .then(left.line.cmp(&right.line))
        .then(left.column.cmp(&right.column))
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
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

fn severity_badge_spans(counts: &SeverityCounts) -> Vec<Span<'static>> {
    let mut spans = Vec::new();

    for (severity, count) in [
        (Severity::Critical, counts.critical),
        (Severity::High, counts.high),
        (Severity::Medium, counts.medium),
        (Severity::Low, counts.low),
    ] {
        if count == 0 {
            continue;
        }

        if !spans.is_empty() {
            spans.push(Span::raw("  "));
        }
        spans.push(severity_count_badge(severity, count));
    }

    spans
}

fn severity_count_badge(severity: Severity, count: usize) -> Span<'static> {
    let label = match severity {
        Severity::Critical => format!(" {} critical ", count),
        Severity::High => format!(" {} high ", count),
        Severity::Medium => format!(" {} medium ", count),
        Severity::Low => format!(" {} low ", count),
    };

    Span::styled(label, severity_badge_style(severity))
}

fn severity_badge_span(severity: Severity) -> Span<'static> {
    let label = match severity {
        Severity::Critical => " CRITICAL ",
        Severity::High => " HIGH ",
        Severity::Medium => " MEDIUM ",
        Severity::Low => " LOW ",
    };

    Span::styled(label.to_string(), severity_badge_style(severity))
}

fn severity_badge_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::default()
            .bg(Color::Rgb(130, 50, 180))
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
        Severity::High => Style::default()
            .bg(Color::Red)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
        Severity::Medium => Style::default()
            .bg(Color::Yellow)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD),
        Severity::Low => Style::default()
            .bg(Color::Blue)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    }
}

fn flow_accent_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Rgb(130, 50, 180),
        Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Blue,
    }
}

fn section_heading(label: &str, color: Color) -> Line<'static> {
    Line::from(Span::styled(
        label.to_string(),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    ))
}

fn metadata_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{}: ", label),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(value.to_string()),
    ])
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

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical+",
        Severity::High => "high+",
        Severity::Medium => "medium+",
        Severity::Low => "low+",
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
const CONTEXT_LINE_MAX_CHARS: usize = 96;
const CONTEXT_FOCUS_LEAD: usize = 28;

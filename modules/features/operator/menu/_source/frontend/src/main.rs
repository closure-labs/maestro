use std::cmp::{max, min};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::io::{self, Stdout};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Color, Line, Modifier, Span, Style};
use ratatui::symbols::border;
use ratatui::text::Text;
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::{Frame, Terminal};
use serde::Deserialize;
use serde_json::Value;

type Backend = CrosstermBackend<Stdout>;
type AppTerminal = Terminal<Backend>;

const UPDATE_TIMEOUT_SECS: u64 = 120;
const MAX_LOG_ENTRIES: usize = 160;
const COLOR_BG_OUTER: Color = Color::Rgb(0x1C, 0x1B, 0x34);
const COLOR_BG_INNER: Color = Color::Rgb(0x1A, 0x1A, 0x22);
const COLOR_BG_FOCUSED: Color = Color::Rgb(0x22, 0x21, 0x3A);
const COLOR_FG_MAIN: Color = Color::Rgb(0xF7, 0xF7, 0xF9);
const COLOR_ACCENT: Color = Color::Rgb(0x87, 0x7C, 0xFC);
const COLOR_ACCENT_SOFT: Color = Color::Rgb(0x6B, 0x6B, 0xD7);
const COLOR_DANGER: Color = Color::Rgb(0xFF, 0x00, 0x25);
const COLOR_MUTED: Color = Color::Rgb(0xD4, 0xD4, 0xD7);
const COLOR_MUTED_2: Color = Color::Rgb(0xAD, 0xAD, 0xB1);
const COLOR_BORDER_DIM: Color = Color::Rgb(0x4A, 0x4A, 0x52);
const COLOR_BORDER_MID: Color = Color::Rgb(0x73, 0x73, 0x7A);
const COLOR_WARNING: Color = Color::Rgb(0xC1, 0xC1, 0xC7);
const COLOR_SUCCESS: Color = Color::Rgb(0x87, 0x7C, 0xFC);
const COLOR_INFO: Color = Color::Rgb(0x6B, 0x6B, 0xD7);
const PANEL_LABEL_WIDTH: usize = 18;
const HEADER_LABEL_WIDTH: usize = 8;
const TRACKED_PATHS: &[&str] = &[
    "AGENTS.md",
    "CHANGELOG.md",
    "README.md",
    "docs",
    "flake.lock",
    "flake.nix",
    "host",
    "lib",
    "modules",
    "pkgs",
    "scripts",
];

#[derive(Clone, Debug)]
struct ActionItem {
    kind: ActionKind,
    title: &'static str,
    detail: &'static str,
}

#[derive(Clone, Debug)]
struct UpdateItem {
    title: &'static str,
    detail: &'static str,
    backend: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    hostname: String,
    username: String,
    timezone: String,
    extras: bool,
    #[serde(default)]
    development_mode: bool,
    ssh_keys: Vec<String>,
    system_packages: Vec<String>,
    user_packages: Vec<String>,
    services: Vec<String>,
    dirty_count: u32,
    head: String,
    branch: String,
    upstream: Option<String>,
    ahead: u32,
    behind: u32,
    memory_total_bytes: u64,
    memory_used_bytes: u64,
    memory_used_percent: u32,
    storage_total_bytes: u64,
    storage_used_bytes: u64,
    storage_used_percent: u32,
    primary_ip: Option<String>,
    xen_orchestra_version: Option<String>,
    web_ui_url: Option<String>,
    rebuild_queued: bool,
    rebuild_needed: bool,
    last_apply: Option<ApplyState>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplyState {
    result: String,
    action: String,
    hostname: String,
    head: String,
    first_install: bool,
    exit_code: i32,
    timestamp: String,
}

#[derive(Debug, Deserialize)]
struct FlakeLock {
    nodes: HashMap<String, LockNode>,
}

#[derive(Debug, Deserialize)]
struct LockNode {
    locked: Option<Value>,
}

#[derive(Debug, Clone)]
enum UpdateStatus {
    Idle,
    Checking,
    UpToDate,
    Available(usize),
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Status,
    HostSetup,
    Access,
    Packages,
    Updates,
    Maintenance,
    Logs,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    PrimaryMenu,
    Options,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfirmChoice {
    Yes,
    No,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionKind {
    RefreshSnapshot,
    CheckForUpdates,
    ToggleExtras,
    ToggleDevelopmentMode,
    AddSshKey,
    ReplaceSshKeys,
    DeleteSelectedSshKey,
    AddSystemPackage,
    AddUserPackage,
    AddService,
    ApplyConfiguration,
    RollbackGeneration,
    RunGarbageCollection,
    RebootSystem,
    ShutdownSystem,
    CleanupUnmanagedUsers,
    FilterLogs,
    ClearLogFilter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogOption {
    Filter,
    ClearFilter,
    Newer,
    Older,
    PageNewer,
    PageOlder,
    Newest,
    Oldest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuOption {
    Action(ActionKind),
    Update(usize),
    SshKey(usize),
    Log(LogOption),
    OpenShell,
}

#[derive(Debug, Clone, Copy)]
enum InputAction {
    SetPrimaryKey,
    AddKey,
    AddSystemPackage,
    AddUserPackage,
    AddService,
    ConfirmCleanupUnmanagedUsers,
    SetLogFilter,
    CommitAndApplyConfiguration,
}

#[derive(Debug, Clone, Copy)]
enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
struct AlertItem {
    severity: Severity,
    message: String,
    action_label: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct InputModal {
    title: String,
    help: String,
    action: InputAction,
    value: String,
    changed_files: Vec<String>,
}

#[derive(Debug, Clone)]
struct CommandPalette {
    query: String,
    selected: usize,
}

#[derive(Debug, Clone)]
struct PaletteEntry {
    title: String,
    detail: String,
    action: PaletteAction,
}

#[derive(Debug, Clone)]
struct GitStatusEntry {
    status: String,
    path: String,
}

#[derive(Debug, Clone)]
enum PaletteAction {
    SwitchPage(Page),
    RunAction(ActionKind),
    OpenShell,
    OpenHelp,
}

#[derive(Debug)]
struct App {
    repo_root: PathBuf,
    snapshot: Snapshot,
    update_status: UpdateStatus,
    update_rx: Option<Receiver<UpdateStatus>>,
    page: Page,
    focus: Focus,
    page_selection: [usize; 8],
    selected_update: usize,
    selected_key: usize,
    selected_alert: usize,
    modal: Option<InputModal>,
    command_palette: Option<CommandPalette>,
    help_open: bool,
    quit_confirm: bool,
    quit_confirm_selection: ConfirmChoice,
    logs: Vec<String>,
    log_filter: String,
    log_scroll: usize,
    should_quit: bool,
    should_open_shell: bool,
    tick: usize,
}

const STATUS_ACTIONS: [ActionItem; 2] = [
    ActionItem {
        kind: ActionKind::RefreshSnapshot,
        title: "Refresh Snapshot",
        detail: "Reload host state, repository status, and current appliance health.",
    },
    ActionItem {
        kind: ActionKind::CheckForUpdates,
        title: "Check for Updates",
        detail: "Open Updates and re-run the flake input lock check.",
    },
];

const HOST_SETUP_ACTIONS: [ActionItem; 2] = [
    ActionItem {
        kind: ActionKind::ToggleExtras,
        title: "Extras",
        detail: "Enable or disable the extras feature set and commit the resulting menu override.",
    },
    ActionItem {
        kind: ActionKind::ToggleDevelopmentMode,
        title: "Development Mode",
        detail: "Enable or disable devenv, Rust, Node.js, and Redis/Valkey helper tooling.",
    },
];

const ACCESS_ACTIONS: [ActionItem; 3] = [
    ActionItem {
        kind: ActionKind::AddSshKey,
        title: "Add SSH Key",
        detail: "Append a public key to the managed SSH authorized key list.",
    },
    ActionItem {
        kind: ActionKind::ReplaceSshKeys,
        title: "Replace SSH Keys",
        detail: "Replace the managed SSH key list with a single public key line.",
    },
    ActionItem {
        kind: ActionKind::DeleteSelectedSshKey,
        title: "Delete Selected Key",
        detail: "Remove the currently selected managed SSH public key.",
    },
];

const PACKAGE_ACTIONS: [ActionItem; 3] = [
    ActionItem {
        kind: ActionKind::AddSystemPackage,
        title: "System Packages",
        detail: "Append a nixpkgs attribute path to the generated host/menu.nix override.",
    },
    ActionItem {
        kind: ActionKind::AddUserPackage,
        title: "User Packages",
        detail: "Append a Home Manager package path to the generated host/menu.nix override.",
    },
    ActionItem {
        kind: ActionKind::AddService,
        title: "Services",
        detail: "Enable a service by dotted NixOS option path in host/menu.nix.",
    },
];

const MAINTENANCE_ACTIONS: [ActionItem; 6] = [
    ActionItem {
        kind: ActionKind::ApplyConfiguration,
        title: "Apply Configuration",
        detail: "Run maestroctl apply for the current host and refresh console state after completion.",
    },
    ActionItem {
        kind: ActionKind::RollbackGeneration,
        title: "Rollback Generation",
        detail: "Run maestroctl rollback interactively for the current host.",
    },
    ActionItem {
        kind: ActionKind::RunGarbageCollection,
        title: "Run Garbage Collection",
        detail: "Run nh clean all interactively for a full manual store cleanup.",
    },
    ActionItem {
        kind: ActionKind::RebootSystem,
        title: "Reboot System",
        detail: "Run systemctl reboot through wrapper sudo for a clean systemd-managed reboot.",
    },
    ActionItem {
        kind: ActionKind::ShutdownSystem,
        title: "Shut Down System",
        detail: "Run systemctl poweroff through wrapper sudo for a clean systemd-managed shutdown.",
    },
    ActionItem {
        kind: ActionKind::CleanupUnmanagedUsers,
        title: "Cleanup Unmanaged Users",
        detail: "Remove non-system users outside the flake-managed admin account and delete their home data after confirmation.",
    },
];

const LOG_ACTIONS: [ActionItem; 2] = [
    ActionItem {
        kind: ActionKind::FilterLogs,
        title: "Filter Logs",
        detail: "Set a substring filter for Recent Activity and the dedicated Logs page.",
    },
    ActionItem {
        kind: ActionKind::ClearLogFilter,
        title: "Clear Log Filter",
        detail:
            "Clear the current activity log filter and reset log scrolling to the newest entries.",
    },
];

const UPDATE_ACTIONS: [UpdateItem; 5] = [
    UpdateItem {
        title: "Update nixpkgs",
        detail: "Refresh only the nixpkgs lock entry and then choose whether to rebuild now or on reboot.",
        backend: "update-nixpkgs",
    },
    UpdateItem {
        title: "Update Home Manager",
        detail: "Refresh only the home-manager lock entry and then choose whether to rebuild now or on reboot.",
        backend: "update-home-manager",
    },
    UpdateItem {
        title: "Update Determinate",
        detail: "Refresh only the determinate lock entry and then choose whether to rebuild now or on reboot.",
        backend: "update-determinate",
    },
    UpdateItem {
        title: "Update XOA",
        detail: "Refresh the xo-nixpkg input and selected package channel, then choose whether to rebuild now or on reboot.",
        backend: "update-xoa",
    },
    UpdateItem {
        title: "Update all",
        detail: "Run a full nix flake update and then choose whether to rebuild now or on reboot.",
        backend: "update-all",
    },
];

impl App {
    fn new(repo_root: PathBuf, snapshot: Snapshot) -> Self {
        let mut app = Self {
            repo_root,
            snapshot,
            update_status: UpdateStatus::Idle,
            update_rx: None,
            page: Page::Status,
            focus: Focus::PrimaryMenu,
            page_selection: [0; 8],
            selected_update: 0,
            selected_key: 0,
            selected_alert: 0,
            modal: None,
            command_palette: None,
            help_open: false,
            quit_confirm: false,
            quit_confirm_selection: ConfirmChoice::No,
            logs: vec![
                "Maestro console ready.".to_string(),
                "Use Up/Down to choose, Enter to advance, and Esc to go back.".to_string(),
            ],
            log_filter: String::new(),
            log_scroll: 0,
            should_quit: false,
            should_open_shell: false,
            tick: 0,
        };
        app.clamp_selection_state();
        app
    }

    fn page_index(page: Page) -> usize {
        match page {
            Page::Status => 0,
            Page::HostSetup => 1,
            Page::Access => 2,
            Page::Packages => 3,
            Page::Updates => 4,
            Page::Maintenance => 5,
            Page::Logs => 6,
            Page::Shell => 7,
        }
    }

    fn current_page_actions(&self) -> &'static [ActionItem] {
        page_actions(self.page)
    }

    fn current_selection(&self) -> usize {
        self.page_selection[Self::page_index(self.page)]
    }

    fn current_selection_mut(&mut self) -> &mut usize {
        &mut self.page_selection[Self::page_index(self.page)]
    }

    fn option_len(&self) -> usize {
        self.menu_options().len()
    }

    fn menu_options(&self) -> Vec<MenuOption> {
        match self.page {
            Page::Status | Page::HostSetup | Page::Packages | Page::Maintenance => self
                .current_page_actions()
                .iter()
                .map(|action| MenuOption::Action(action.kind))
                .collect(),
            Page::Access => {
                let mut options = ACCESS_ACTIONS
                    .iter()
                    .map(|action| MenuOption::Action(action.kind))
                    .collect::<Vec<_>>();
                options.extend((0..self.snapshot.ssh_keys.len()).map(MenuOption::SshKey));
                options
            }
            Page::Updates => (0..UPDATE_ACTIONS.len()).map(MenuOption::Update).collect(),
            Page::Logs => vec![
                MenuOption::Log(LogOption::Filter),
                MenuOption::Log(LogOption::ClearFilter),
                MenuOption::Log(LogOption::Newer),
                MenuOption::Log(LogOption::Older),
                MenuOption::Log(LogOption::PageNewer),
                MenuOption::Log(LogOption::PageOlder),
                MenuOption::Log(LogOption::Newest),
                MenuOption::Log(LogOption::Oldest),
            ],
            Page::Shell => vec![MenuOption::OpenShell],
        }
    }

    fn selected_menu_option(&self) -> Option<MenuOption> {
        self.menu_options().get(self.current_selection()).copied()
    }

    fn selected_page_action(&self) -> Option<&'static ActionItem> {
        match self.selected_menu_option() {
            Some(MenuOption::Action(kind)) => action_item(kind),
            _ => None,
        }
    }

    fn selected_sidebar_title(&self) -> String {
        match self.selected_menu_option() {
            Some(MenuOption::Action(kind)) => action_item(kind)
                .map(|item| item.title.to_string())
                .unwrap_or_else(|| "Action".to_string()),
            Some(MenuOption::Update(index)) => UPDATE_ACTIONS
                .get(index)
                .map(|item| item.title.to_string())
                .unwrap_or_else(|| "Update target".to_string()),
            Some(MenuOption::SshKey(index)) => format!("SSH Key {}", index + 1),
            Some(MenuOption::Log(option)) => log_option_title(option).to_string(),
            Some(MenuOption::OpenShell) | None => "Open Shell".to_string(),
        }
    }

    fn selected_sidebar_detail(&self) -> String {
        match self.selected_menu_option() {
            Some(MenuOption::Action(kind)) => action_item(kind)
                .map(|item| item.detail.to_string())
                .unwrap_or_else(|| "Run the selected action.".to_string()),
            Some(MenuOption::Update(index)) => UPDATE_ACTIONS
                .get(index)
                .map(|item| item.detail.to_string())
                .unwrap_or_else(|| "Run the selected flake input update.".to_string()),
            Some(MenuOption::SshKey(index)) => self
                .snapshot
                .ssh_keys
                .get(index)
                .map(|key| truncate_middle(key, 96))
                .unwrap_or_else(|| "No SSH key selected.".to_string()),
            Some(MenuOption::Log(option)) => log_option_detail(option).to_string(),
            Some(MenuOption::OpenShell) | None => {
                "Leave the TUI and exec the configured login shell with TUI bypass enabled."
                    .to_string()
            }
        }
    }

    fn page_title(&self) -> &'static str {
        page_label(self.page)
    }

    fn set_page(&mut self, page: Page) {
        let keep_primary = self.focus == Focus::PrimaryMenu;
        self.page = page;
        self.clamp_selection_state();
        self.focus = if keep_primary {
            Focus::PrimaryMenu
        } else {
            Focus::Options
        };
    }

    fn next_page(&mut self) {
        self.set_page(match self.page {
            Page::Status => Page::HostSetup,
            Page::HostSetup => Page::Access,
            Page::Access => Page::Packages,
            Page::Packages => Page::Updates,
            Page::Updates => Page::Maintenance,
            Page::Maintenance => Page::Logs,
            Page::Logs => Page::Shell,
            Page::Shell => Page::Status,
        });
    }

    fn previous_page(&mut self) {
        self.set_page(match self.page {
            Page::Status => Page::Shell,
            Page::HostSetup => Page::Status,
            Page::Access => Page::HostSetup,
            Page::Packages => Page::Access,
            Page::Updates => Page::Packages,
            Page::Maintenance => Page::Updates,
            Page::Logs => Page::Maintenance,
            Page::Shell => Page::Logs,
        });
    }

    fn set_focus(&mut self, focus: Focus) {
        self.focus = focus;
    }

    fn open_quit_confirm(&mut self) {
        self.quit_confirm = true;
        self.quit_confirm_selection = ConfirmChoice::No;
    }

    fn toggle_quit_confirm_selection(&mut self) {
        self.quit_confirm_selection = match self.quit_confirm_selection {
            ConfirmChoice::Yes => ConfirmChoice::No,
            ConfirmChoice::No => ConfirmChoice::Yes,
        };
    }

    fn move_sidebar_up(&mut self) -> bool {
        if self.current_selection() == 0 {
            false
        } else {
            *self.current_selection_mut() -= 1;
            true
        }
    }

    fn move_sidebar_down(&mut self) -> bool {
        let next = self.current_selection() + 1;
        if next >= self.option_len() {
            false
        } else {
            *self.current_selection_mut() = next;
            true
        }
    }

    fn sync_selected_option_state(&mut self) {
        match self.selected_menu_option() {
            Some(MenuOption::Update(index)) => self.selected_update = index,
            Some(MenuOption::SshKey(index)) => self.selected_key = index,
            _ => {}
        }
    }

    fn focus_is(&self, focus: Focus) -> bool {
        self.focus == focus
    }

    fn start_update_check(&mut self) {
        if matches!(self.update_status, UpdateStatus::Checking) {
            return;
        }

        self.update_status = UpdateStatus::Checking;
        let repo_root = self.repo_root.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let status = check_flake_updates(&repo_root);
            let _ = tx.send(status);
        });
        self.update_rx = Some(rx);
    }

    fn poll_background(&mut self) {
        if let Some(rx) = &self.update_rx {
            if let Ok(status) = rx.try_recv() {
                match &status {
                    UpdateStatus::UpToDate => {
                        self.push_log("Flake input check: inputs are up to date.");
                    }
                    UpdateStatus::Available(count) => {
                        self.push_log(format!(
                            "Flake input check: {count} input lock entries can be updated."
                        ));
                    }
                    UpdateStatus::Error(message) => {
                        self.push_log(format!("Flake input check failed: {message}"));
                    }
                    UpdateStatus::Idle | UpdateStatus::Checking => {}
                }
                self.update_status = status;
                self.update_rx = None;
            }
        }
    }

    fn refresh_snapshot(&mut self) -> Result<()> {
        self.snapshot = load_snapshot(&self.repo_root)?;
        self.clamp_selection_state();
        Ok(())
    }

    fn clamp_selection_state(&mut self) {
        let option_len = self.option_len();
        if self.current_selection() >= option_len {
            *self.current_selection_mut() = option_len.saturating_sub(1);
        }

        self.selected_update = min(self.selected_update, UPDATE_ACTIONS.len().saturating_sub(1));

        if self.snapshot.ssh_keys.is_empty() {
            self.selected_key = 0;
        } else if self.selected_key >= self.snapshot.ssh_keys.len() {
            self.selected_key = self.snapshot.ssh_keys.len() - 1;
        }

        let alert_count = self.alerts().len();
        if alert_count == 0 {
            self.selected_alert = 0;
        } else if self.selected_alert >= alert_count {
            self.selected_alert = alert_count - 1;
        }

        let filtered_count = self.filtered_logs().len();
        if filtered_count == 0 {
            self.log_scroll = 0;
        } else {
            self.log_scroll = min(self.log_scroll, filtered_count.saturating_sub(1));
        }

        self.sync_selected_option_state();
    }

    fn push_log(&mut self, message: impl Into<String>) {
        self.logs.push(message.into());
        if self.logs.len() > MAX_LOG_ENTRIES {
            let drain = self.logs.len() - MAX_LOG_ENTRIES;
            self.logs.drain(0..drain);
        }
        self.clamp_selection_state();
    }

    fn alerts(&self) -> Vec<AlertItem> {
        let mut alerts = Vec::new();

        if self.snapshot.dirty_count > 0 {
            alerts.push(AlertItem {
                severity: Severity::Warning,
                message: format!(
                    "{} tracked repository changes are still uncommitted.",
                    self.snapshot.dirty_count
                ),
                action_label: Some("Open Logs"),
            });
        }

        if self.snapshot.rebuild_needed {
            alerts.push(AlertItem {
                severity: Severity::Warning,
                message: "Current repository state has not been switched onto the host."
                    .to_string(),
                action_label: Some("Apply now"),
            });
        }

        if self.snapshot.rebuild_queued {
            alerts.push(AlertItem {
                severity: Severity::Info,
                message: "A rebuild has been queued for the next boot.".to_string(),
                action_label: Some("Maintenance"),
            });
        }

        if self.snapshot.behind > 0 {
            alerts.push(AlertItem {
                severity: Severity::Warning,
                message: format!(
                    "Local branch is behind {} by {} commits.",
                    self.snapshot
                        .upstream
                        .clone()
                        .unwrap_or_else(|| "its upstream".to_string()),
                    self.snapshot.behind
                ),
                action_label: Some("Check updates"),
            });
        }

        if self.snapshot.ahead > 0 {
            alerts.push(AlertItem {
                severity: Severity::Info,
                message: format!(
                    "Local branch is ahead of upstream by {} commits.",
                    self.snapshot.ahead
                ),
                action_label: Some("Open Logs"),
            });
        }

        if self.snapshot.memory_used_percent >= 90 {
            alerts.push(AlertItem {
                severity: Severity::Error,
                message: format!(
                    "RAM usage is high: {}.",
                    format_usage(
                        self.snapshot.memory_used_bytes,
                        self.snapshot.memory_total_bytes,
                        self.snapshot.memory_used_percent
                    )
                ),
                action_label: None,
            });
        } else if self.snapshot.memory_used_percent >= 75 {
            alerts.push(AlertItem {
                severity: Severity::Warning,
                message: format!(
                    "RAM usage is elevated: {}.",
                    format_usage(
                        self.snapshot.memory_used_bytes,
                        self.snapshot.memory_total_bytes,
                        self.snapshot.memory_used_percent
                    )
                ),
                action_label: None,
            });
        }

        if self.snapshot.storage_used_percent >= 90 {
            alerts.push(AlertItem {
                severity: Severity::Error,
                message: format!(
                    "Root storage usage is high: {}.",
                    format_usage(
                        self.snapshot.storage_used_bytes,
                        self.snapshot.storage_total_bytes,
                        self.snapshot.storage_used_percent
                    )
                ),
                action_label: None,
            });
        } else if self.snapshot.storage_used_percent >= 75 {
            alerts.push(AlertItem {
                severity: Severity::Warning,
                message: format!(
                    "Root storage usage is elevated: {}.",
                    format_usage(
                        self.snapshot.storage_used_bytes,
                        self.snapshot.storage_total_bytes,
                        self.snapshot.storage_used_percent
                    )
                ),
                action_label: None,
            });
        }

        if self.snapshot.primary_ip.is_none() {
            alerts.push(AlertItem {
                severity: Severity::Warning,
                message: "No primary IPv4 address was detected.".to_string(),
                action_label: None,
            });
        }

        match &self.update_status {
            UpdateStatus::Available(count) => alerts.push(AlertItem {
                severity: Severity::Info,
                message: format!("{count} flake input lock entries can be updated."),
                action_label: Some("Check updates"),
            }),
            UpdateStatus::Error(message) => alerts.push(AlertItem {
                severity: Severity::Error,
                message: format!("Flake input check failed: {message}"),
                action_label: Some("Check updates"),
            }),
            UpdateStatus::Idle | UpdateStatus::Checking | UpdateStatus::UpToDate => {}
        }

        if let Some(last_apply) = &self.snapshot.last_apply {
            if last_apply.result != "success" {
                alerts.push(AlertItem {
                    severity: Severity::Error,
                    message: format!(
                        "Last {} failed at {} with exit code {}.",
                        last_apply.action, last_apply.timestamp, last_apply.exit_code
                    ),
                    action_label: Some("Open Logs"),
                });
            }
        } else {
            alerts.push(AlertItem {
                severity: Severity::Warning,
                message: "No successful host switch has been recorded yet.".to_string(),
                action_label: Some("Apply now"),
            });
        }

        if alerts.is_empty() {
            alerts.push(AlertItem {
                severity: Severity::Info,
                message: "No outstanding alerts.".to_string(),
                action_label: None,
            });
        }

        alerts
    }

    fn filtered_logs(&self) -> Vec<String> {
        let query = self.log_filter.trim().to_lowercase();
        let iter = self.logs.iter().rev();
        if query.is_empty() {
            iter.cloned().collect()
        } else {
            iter.filter(|line| line.to_lowercase().contains(&query))
                .cloned()
                .collect()
        }
    }

    fn palette_entries(&self) -> Vec<PaletteEntry> {
        let mut entries = vec![
            PaletteEntry {
                title: "Go to Status".to_string(),
                detail: "Switch to the Status section.".to_string(),
                action: PaletteAction::SwitchPage(Page::Status),
            },
            PaletteEntry {
                title: "Go to Host Setup".to_string(),
                detail: "Switch to the Host Setup section.".to_string(),
                action: PaletteAction::SwitchPage(Page::HostSetup),
            },
            PaletteEntry {
                title: "Go to Access".to_string(),
                detail: "Switch to the Access section.".to_string(),
                action: PaletteAction::SwitchPage(Page::Access),
            },
            PaletteEntry {
                title: "Go to Packages".to_string(),
                detail: "Switch to the Packages section.".to_string(),
                action: PaletteAction::SwitchPage(Page::Packages),
            },
            PaletteEntry {
                title: "Go to Updates".to_string(),
                detail: "Switch to the Updates section.".to_string(),
                action: PaletteAction::SwitchPage(Page::Updates),
            },
            PaletteEntry {
                title: "Go to Maintenance".to_string(),
                detail: "Switch to the Maintenance section.".to_string(),
                action: PaletteAction::SwitchPage(Page::Maintenance),
            },
            PaletteEntry {
                title: "Go to Logs".to_string(),
                detail: "Switch to the Logs section.".to_string(),
                action: PaletteAction::SwitchPage(Page::Logs),
            },
            PaletteEntry {
                title: "Open Help".to_string(),
                detail: "Show the full navigation reference.".to_string(),
                action: PaletteAction::OpenHelp,
            },
            PaletteEntry {
                title: "Open Shell".to_string(),
                detail: "Leave the TUI and exec the configured login shell.".to_string(),
                action: PaletteAction::OpenShell,
            },
        ];

        for page in [
            Page::Status,
            Page::HostSetup,
            Page::Access,
            Page::Packages,
            Page::Updates,
            Page::Maintenance,
            Page::Logs,
        ] {
            for action in page_actions(page) {
                entries.push(PaletteEntry {
                    title: format!("{} / {}", page_label(page), action.title),
                    detail: action.detail.to_string(),
                    action: PaletteAction::RunAction(action.kind),
                });
            }
        }

        let query = self
            .command_palette
            .as_ref()
            .map(|palette| palette.query.trim().to_lowercase())
            .unwrap_or_default();

        if query.is_empty() {
            entries
        } else {
            entries
                .into_iter()
                .filter(|entry| {
                    entry.title.to_lowercase().contains(&query)
                        || entry.detail.to_lowercase().contains(&query)
                })
                .collect()
        }
    }
}

fn page_actions(page: Page) -> &'static [ActionItem] {
    match page {
        Page::Status => &STATUS_ACTIONS,
        Page::HostSetup => &HOST_SETUP_ACTIONS,
        Page::Access => &ACCESS_ACTIONS,
        Page::Packages => &PACKAGE_ACTIONS,
        Page::Updates => &[],
        Page::Maintenance => &MAINTENANCE_ACTIONS,
        Page::Logs => &LOG_ACTIONS,
        Page::Shell => &[],
    }
}

fn primary_pages() -> &'static [Page] {
    &[
        Page::Status,
        Page::HostSetup,
        Page::Access,
        Page::Packages,
        Page::Updates,
        Page::Maintenance,
        Page::Logs,
        Page::Shell,
    ]
}

fn action_item(kind: ActionKind) -> Option<&'static ActionItem> {
    primary_pages()
        .iter()
        .flat_map(|page| page_actions(*page).iter())
        .find(|item| item.kind == kind)
}

fn log_option_title(option: LogOption) -> &'static str {
    match option {
        LogOption::Filter => "Filter Logs",
        LogOption::ClearFilter => "Clear Filter",
        LogOption::Newer => "Scroll Newer",
        LogOption::Older => "Scroll Older",
        LogOption::PageNewer => "Page Newer",
        LogOption::PageOlder => "Page Older",
        LogOption::Newest => "Newest Entry",
        LogOption::Oldest => "Oldest Entry",
    }
}

fn log_option_detail(option: LogOption) -> &'static str {
    match option {
        LogOption::Filter => "Set a substring filter for the recent activity log.",
        LogOption::ClearFilter => "Clear the current activity filter and return to newest entries.",
        LogOption::Newer => "Move the log preview one entry toward newer activity.",
        LogOption::Older => "Move the log preview one entry toward older activity.",
        LogOption::PageNewer => "Move the log preview one page toward newer activity.",
        LogOption::PageOlder => "Move the log preview one page toward older activity.",
        LogOption::Newest => "Jump the log preview to the newest matching activity.",
        LogOption::Oldest => "Jump the log preview to the oldest matching activity.",
    }
}

fn option_label(app: &App, option: MenuOption) -> (String, String) {
    match option {
        MenuOption::Action(kind) => (
            action_item(kind)
                .map(|item| item.title.to_string())
                .unwrap_or_else(|| "Action".to_string()),
            "  ".to_string(),
        ),
        MenuOption::Update(index) => (
            UPDATE_ACTIONS
                .get(index)
                .map(|item| item.title.to_string())
                .unwrap_or_else(|| "Update target".to_string()),
            "  ".to_string(),
        ),
        MenuOption::SshKey(index) => (
            app.snapshot
                .ssh_keys
                .get(index)
                .map(|key| truncate_middle(key, 28))
                .unwrap_or_else(|| "SSH key".to_string()),
            "  ".to_string(),
        ),
        MenuOption::Log(option) => (log_option_title(option).to_string(), "  ".to_string()),
        MenuOption::OpenShell => ("Return to Shell".to_string(), "  ".to_string()),
    }
}

fn page_label(page: Page) -> &'static str {
    match page {
        Page::Status => "Status",
        Page::HostSetup => "Host Setup",
        Page::Access => "Access",
        Page::Packages => "Packages",
        Page::Updates => "Updates",
        Page::Maintenance => "Maintenance",
        Page::Logs => "Logs",
        Page::Shell => "Shell",
    }
}

fn primary_page_detail(page: Page) -> &'static str {
    match page {
        Page::Status => "Host health, repository state, alerts, and recent activity.",
        Page::HostSetup => {
            "Hostname, primary username, Extras, Development Mode, and host identity actions."
        }
        Page::Access => "Managed SSH keys and access maintenance.",
        Page::Packages => "System packages, user packages, and service enablement.",
        Page::Updates => "Flake input update targets and rebuild state.",
        Page::Maintenance => "Apply, rollback, cleanup, reboot, and shutdown workflows.",
        Page::Logs => "Activity filters, navigation controls, and log preview.",
        Page::Shell => "Leave the console and return to the login shell.",
    }
}

fn main() -> Result<()> {
    let repo_root = discover_repo_root()?;
    let snapshot = load_snapshot(&repo_root)?;
    let mut app = App::new(repo_root, snapshot);
    app.start_update_check();

    let mut terminal = init_terminal()?;
    let run_result = run_app(&mut terminal, &mut app);
    restore_terminal(&mut terminal)?;

    if app.should_open_shell {
        open_shell();
    }

    run_result
}

fn discover_repo_root() -> Result<PathBuf> {
    if let Some(root) = env::var_os("MAESTRO_SYSTEM_ROOT") {
        let candidate = PathBuf::from(root);
        if candidate.join("modules/features/operator/menu/_source/backend/state.sh").is_file() {
            return Ok(candidate);
        }
    }

    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
    {
        if output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() {
                return Ok(PathBuf::from(value));
            }
        }
    }

    if let Some(home) = env::var_os("HOME") {
        for name in ["maestro", "system"] {
            let candidate = PathBuf::from(&home).join(name);
            if candidate.join("modules/features/operator/menu/_source/backend/state.sh").is_file() {
                return Ok(candidate);
            }
        }
    }

    env::current_dir().context("failed to determine current directory for MAESTRO_SYSTEM_ROOT")
}

fn init_terminal() -> Result<AppTerminal> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).context("failed to initialize terminal")
}

fn restore_terminal(terminal: &mut AppTerminal) -> Result<()> {
    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")
}

fn suspend_terminal(terminal: &mut AppTerminal) -> Result<()> {
    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")
}

fn resume_terminal(terminal: &mut AppTerminal) -> Result<()> {
    enable_raw_mode().context("failed to re-enable raw mode")?;
    execute!(terminal.backend_mut(), EnterAlternateScreen)
        .context("failed to re-enter alternate screen")?;
    terminal.clear().context("failed to clear terminal")
}

fn load_snapshot(repo_root: &Path) -> Result<Snapshot> {
    let output = Command::new(repo_root.join("modules/features/operator/menu/_source/backend/state.sh"))
        .arg("--json")
        .env("MAESTRO_SYSTEM_ROOT", repo_root)
        .output()
        .with_context(|| {
            format!(
                "failed to run {}",
                repo_root.join("modules/features/operator/menu/_source/backend/state.sh").display()
            )
        })?;

    if !output.status.success() {
        return Err(anyhow!(
            "state backend failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    serde_json::from_slice(&output.stdout).context("failed to parse state backend JSON")
}

fn run_app(terminal: &mut AppTerminal, app: &mut App) -> Result<()> {
    loop {
        app.poll_background();
        app.tick = app.tick.wrapping_add(1);
        terminal.draw(|frame| render(frame, app))?;

        if app.should_quit || app.should_open_shell {
            return Ok(());
        }

        if event::poll(Duration::from_millis(200)).context("failed to poll terminal events")? {
            if let Event::Key(key) = event::read().context("failed to read terminal event")? {
                if key.kind == KeyEventKind::Press {
                    handle_key(terminal, app, key)?;
                }
            }
        }
    }
}

fn handle_key(terminal: &mut AppTerminal, app: &mut App, key: KeyEvent) -> Result<()> {
    if app.command_palette.is_some() {
        return handle_palette_key(app, key);
    }
    if app.help_open {
        return handle_help_key(app, key);
    }
    if app.modal.is_some() {
        return handle_modal_key(terminal, app, key);
    }
    if app.quit_confirm {
        return handle_quit_confirm_key(app, key);
    }

    match key.code {
        KeyCode::Char(':') => {
            app.command_palette = Some(CommandPalette {
                query: String::new(),
                selected: 0,
            });
            return Ok(());
        }
        KeyCode::Char('?') => {
            app.help_open = true;
            return Ok(());
        }
        KeyCode::Esc => {
            if app.focus == Focus::Options {
                app.focus = Focus::PrimaryMenu;
            } else {
                app.open_quit_confirm();
            }
            return Ok(());
        }
        _ => {}
    }

    match app.focus {
        Focus::PrimaryMenu => handle_primary_menu_key(app, key),
        Focus::Options => handle_options_key(terminal, app, key),
    }
}

fn handle_primary_menu_key(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Up => app.previous_page(),
        KeyCode::Down => app.next_page(),
        KeyCode::Enter => {
            if app.page == Page::Shell {
                app.open_quit_confirm();
            } else {
                app.focus = Focus::Options;
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_options_key(terminal: &mut AppTerminal, app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Up => {
            let _ = app.move_sidebar_up();
            app.sync_selected_option_state();
        }
        KeyCode::Down => {
            let _ = app.move_sidebar_down();
            app.sync_selected_option_state();
        }
        KeyCode::Enter => activate_selected_option(terminal, app)?,
        _ => {}
    }

    Ok(())
}

fn handle_modal_key(terminal: &mut AppTerminal, app: &mut App, key: KeyEvent) -> Result<()> {
    let modal = app.modal.as_mut().expect("modal checked above");
    match key.code {
        KeyCode::Esc => app.modal = None,
        KeyCode::Enter => {
            let action = modal.action;
            let value = modal.value.trim().to_string();
            app.modal = None;
            submit_modal(terminal, app, action, value)?;
        }
        KeyCode::Backspace => {
            modal.value.pop();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            modal.value.clear();
        }
        KeyCode::Char(ch) => modal.value.push(ch),
        _ => {}
    }
    Ok(())
}

fn handle_quit_confirm_key(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => app.quit_confirm = false,
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            app.quit_confirm = false;
            app.should_open_shell = true;
        }
        KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down => {
            app.toggle_quit_confirm_selection();
        }
        KeyCode::Enter => match app.quit_confirm_selection {
            ConfirmChoice::Yes => {
                app.quit_confirm = false;
                app.should_open_shell = true;
            }
            ConfirmChoice::No => app.quit_confirm = false,
        },
        _ => {}
    }
    Ok(())
}

fn handle_help_key(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc | KeyCode::Char('?') => app.help_open = false,
        _ => {}
    }
    Ok(())
}

fn handle_palette_key(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => app.command_palette = None,
        KeyCode::Backspace => {
            let palette = app.command_palette.as_mut().expect("palette checked above");
            palette.query.pop();
            palette.selected = 0;
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let palette = app.command_palette.as_mut().expect("palette checked above");
            palette.query.clear();
            palette.selected = 0;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            let len = app.palette_entries().len();
            if len > 0 {
                let palette = app.command_palette.as_mut().expect("palette checked above");
                if palette.selected == 0 {
                    palette.selected = len - 1;
                } else {
                    palette.selected -= 1;
                }
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let len = app.palette_entries().len();
            if len > 0 {
                let palette = app.command_palette.as_mut().expect("palette checked above");
                palette.selected = (palette.selected + 1) % len;
            }
        }
        KeyCode::Enter => {
            let entries = app.palette_entries();
            let selected = app
                .command_palette
                .as_ref()
                .map(|palette| palette.selected)
                .unwrap_or(0);
            let action = entries.get(selected).map(|entry| entry.action.clone());
            app.command_palette = None;
            if let Some(action) = action {
                run_palette_action(app, action)?;
            }
        }
        KeyCode::Char(ch) => {
            let palette = app.command_palette.as_mut().expect("palette checked above");
            palette.query.push(ch);
            palette.selected = 0;
        }
        _ => {}
    }
    Ok(())
}

fn run_palette_action(app: &mut App, action: PaletteAction) -> Result<()> {
    match action {
        PaletteAction::SwitchPage(page) => app.set_page(page),
        PaletteAction::RunAction(kind) => run_quick_action(app, kind)?,
        PaletteAction::OpenShell => app.open_quit_confirm(),
        PaletteAction::OpenHelp => app.help_open = true,
    }
    Ok(())
}

fn run_quick_action(app: &mut App, kind: ActionKind) -> Result<()> {
    match kind {
        ActionKind::RefreshSnapshot => {
            app.refresh_snapshot()?;
            app.start_update_check();
            app.push_log("Refreshed repository snapshot.");
        }
        ActionKind::CheckForUpdates => {
            app.set_page(Page::Updates);
            *app.current_selection_mut() = 0;
            app.set_focus(Focus::Options);
            app.start_update_check();
            app.push_log("Opened Updates.");
        }
        ActionKind::ToggleExtras => run_action_capture(app, &["toggle-extras"])?,
        ActionKind::ToggleDevelopmentMode => run_action_capture(app, &["toggle-development-mode"])?,
        ActionKind::AddSshKey => open_modal(
            app,
            InputAction::AddKey,
            "Add SSH key",
            "Paste a full public key line.",
            "",
        ),
        ActionKind::ReplaceSshKeys => open_modal(
            app,
            InputAction::SetPrimaryKey,
            "Replace SSH keys",
            "Replace the managed key list with a single public key line.",
            "",
        ),
        ActionKind::DeleteSelectedSshKey => {
            if let Some(selected_key) = app.snapshot.ssh_keys.get(app.selected_key).cloned() {
                run_action_capture(app, &["remove-ssh-key", selected_key.as_str()])?;
            } else {
                app.push_log("No SSH key selected for removal.");
            }
        }
        ActionKind::AddSystemPackage => open_modal(
            app,
            InputAction::AddSystemPackage,
            "Add system package",
            "Enter a nixpkgs attribute path such as tailscale or unstable.myPkg.",
            "",
        ),
        ActionKind::AddUserPackage => open_modal(
            app,
            InputAction::AddUserPackage,
            "Add user package",
            "Enter a nixpkgs attribute path for the user package list.",
            "",
        ),
        ActionKind::AddService => open_modal(
            app,
            InputAction::AddService,
            "Add service",
            "Enter a dotted NixOS service path such as tailscale or prometheus.exporters.node.",
            "",
        ),
        ActionKind::ApplyConfiguration
        | ActionKind::RollbackGeneration
        | ActionKind::RunGarbageCollection
        | ActionKind::RebootSystem
        | ActionKind::ShutdownSystem
        | ActionKind::CleanupUnmanagedUsers => {
            app.set_page(Page::Maintenance);
        }
        ActionKind::FilterLogs => {
            app.set_page(Page::Logs);
            let current = app.log_filter.clone();
            open_modal(
                app,
                InputAction::SetLogFilter,
                "Filter logs",
                "Enter a substring to filter Recent Activity entries.",
                current.as_str(),
            );
        }
        ActionKind::ClearLogFilter => {
            app.log_filter.clear();
            app.log_scroll = 0;
            app.push_log("Cleared log filter.");
        }
    }
    Ok(())
}

fn activate_selected_option(terminal: &mut AppTerminal, app: &mut App) -> Result<()> {
    match app.selected_menu_option() {
        Some(MenuOption::Action(kind)) => activate_action_kind(terminal, app, kind)?,
        Some(MenuOption::Update(index)) => {
            app.selected_update = index;
            activate_selected_update(terminal, app)?;
        }
        Some(MenuOption::SshKey(index)) => {
            app.selected_key = index;
        }
        Some(MenuOption::Log(option)) => run_log_option(app, option),
        Some(MenuOption::OpenShell) | None => {
            app.open_quit_confirm();
        }
    }
    Ok(())
}

fn activate_action_kind(terminal: &mut AppTerminal, app: &mut App, kind: ActionKind) -> Result<()> {
    match kind {
        ActionKind::RefreshSnapshot => {
            app.refresh_snapshot()?;
            app.start_update_check();
            app.push_log("Refreshed repository snapshot.");
        }
        ActionKind::CheckForUpdates => {
            app.start_update_check();
            app.set_page(Page::Updates);
            *app.current_selection_mut() = 0;
            app.set_focus(Focus::Options);
        }
        ActionKind::ToggleExtras => run_action_capture(app, &["toggle-extras"])?,
        ActionKind::ToggleDevelopmentMode => run_action_capture(app, &["toggle-development-mode"])?,
        ActionKind::AddSshKey => open_modal(
            app,
            InputAction::AddKey,
            "Add SSH key",
            "Paste a full public key line.",
            "",
        ),
        ActionKind::ReplaceSshKeys => open_modal(
            app,
            InputAction::SetPrimaryKey,
            "Replace SSH keys",
            "Replace the managed key list with a single public key line.",
            "",
        ),
        ActionKind::DeleteSelectedSshKey => {
            if let Some(selected_key) = app.snapshot.ssh_keys.get(app.selected_key).cloned() {
                run_action_capture(app, &["remove-ssh-key", selected_key.as_str()])?;
            } else {
                app.push_log("No SSH key selected for removal.");
            }
        }
        ActionKind::AddSystemPackage => open_modal(
            app,
            InputAction::AddSystemPackage,
            "Add system package",
            "Enter a nixpkgs attribute path such as tailscale or unstable.myPkg.",
            "",
        ),
        ActionKind::AddUserPackage => open_modal(
            app,
            InputAction::AddUserPackage,
            "Add user package",
            "Enter a nixpkgs attribute path for the user package list.",
            "",
        ),
        ActionKind::AddService => open_modal(
            app,
            InputAction::AddService,
            "Add service",
            "Enter a dotted NixOS service path such as tailscale or prometheus.exporters.node.",
            "",
        ),
        ActionKind::ApplyConfiguration => run_apply_configuration(terminal, app)?,
        ActionKind::RollbackGeneration => run_rollback_generation(terminal, app)?,
        ActionKind::RunGarbageCollection => run_garbage_collection(terminal, app)?,
        ActionKind::RebootSystem => run_reboot_system(terminal, app)?,
        ActionKind::ShutdownSystem => run_shutdown_system(terminal, app)?,
        ActionKind::CleanupUnmanagedUsers => open_modal(
            app,
            InputAction::ConfirmCleanupUnmanagedUsers,
            "Cleanup unmanaged users",
            "Type WIPE to remove unmanaged users under /home and delete their home data.",
            "",
        ),
        ActionKind::FilterLogs => {
            let current = app.log_filter.clone();
            open_modal(
                app,
                InputAction::SetLogFilter,
                "Filter logs",
                "Enter a substring to filter Recent Activity entries.",
                current.as_str(),
            )
        }
        ActionKind::ClearLogFilter => {
            app.log_filter.clear();
            app.log_scroll = 0;
            app.push_log("Cleared log filter.");
        }
    }
    Ok(())
}

fn run_log_option(app: &mut App, option: LogOption) {
    let total = app.filtered_logs().len();
    match option {
        LogOption::Filter => {
            let current = app.log_filter.clone();
            open_modal(
                app,
                InputAction::SetLogFilter,
                "Filter logs",
                "Enter a substring to filter Recent Activity entries.",
                current.as_str(),
            );
        }
        LogOption::ClearFilter => {
            app.log_filter.clear();
            app.log_scroll = 0;
            app.push_log("Cleared log filter.");
        }
        LogOption::Newer => {
            app.log_scroll = app.log_scroll.saturating_sub(1);
        }
        LogOption::Older => {
            if total > 0 && app.log_scroll < total.saturating_sub(1) {
                app.log_scroll = min(app.log_scroll + 1, total.saturating_sub(1));
            }
        }
        LogOption::PageNewer => {
            app.log_scroll = app.log_scroll.saturating_sub(10);
        }
        LogOption::PageOlder => {
            if total > 0 {
                app.log_scroll = min(app.log_scroll + 10, total.saturating_sub(1));
            }
        }
        LogOption::Newest => app.log_scroll = 0,
        LogOption::Oldest => {
            if total > 0 {
                app.log_scroll = total - 1;
            }
        }
    }
}

fn submit_modal(
    terminal: &mut AppTerminal,
    app: &mut App,
    action: InputAction,
    value: String,
) -> Result<()> {
    match action {
        InputAction::SetPrimaryKey => {
            if value.is_empty() {
                app.push_log("Ignored empty SSH key.");
            } else {
                run_action_capture(app, &["set-ssh-key", value.as_str()])?;
                app.set_page(Page::Access);
                *app.current_selection_mut() = ACCESS_ACTIONS.len();
                app.set_focus(Focus::Options);
            }
        }
        InputAction::AddKey => {
            if value.is_empty() {
                app.push_log("Ignored empty SSH key.");
            } else {
                run_action_capture(app, &["add-ssh-key", value.as_str()])?;
                app.set_page(Page::Access);
                *app.current_selection_mut() = ACCESS_ACTIONS.len();
                app.set_focus(Focus::Options);
            }
        }
        InputAction::AddSystemPackage => {
            if value.is_empty() {
                app.push_log("Ignored empty package path.");
            } else {
                run_action_capture(app, &["add-system-package", value.as_str()])?;
                app.set_page(Page::Packages);
                *app.current_selection_mut() = 0;
            }
        }
        InputAction::AddUserPackage => {
            if value.is_empty() {
                app.push_log("Ignored empty package path.");
            } else {
                run_action_capture(app, &["add-user-package", value.as_str()])?;
                app.set_page(Page::Packages);
                *app.current_selection_mut() = 1;
            }
        }
        InputAction::AddService => {
            if value.is_empty() {
                app.push_log("Ignored empty service path.");
            } else {
                run_action_capture(app, &["add-service", value.as_str()])?;
                app.set_page(Page::Packages);
                *app.current_selection_mut() = 2;
            }
        }
        InputAction::ConfirmCleanupUnmanagedUsers => {
            if value == "WIPE" {
                run_action_capture(app, &["cleanup-unmanaged-users"])?;
                app.set_page(Page::Maintenance);
                *app.current_selection_mut() = 5;
            } else {
                app.push_log("Cleanup canceled. Type WIPE to confirm unmanaged-user removal.");
            }
        }
        InputAction::SetLogFilter => {
            app.log_filter = value;
            app.log_scroll = 0;
            app.set_page(Page::Logs);
            app.set_focus(Focus::Options);
            if app.log_filter.is_empty() {
                app.push_log("Cleared log filter.");
            } else {
                app.push_log(format!("Set log filter to `{}`.", app.log_filter));
            }
        }
        InputAction::CommitAndApplyConfiguration => {
            if commit_uncommitted_changes(app, value.as_str())? {
                run_apply_command(terminal, app)?;
            }
        }
    }
    Ok(())
}

fn activate_selected_update(terminal: &mut AppTerminal, app: &mut App) -> Result<()> {
    let update = &UPDATE_ACTIONS[app.selected_update];
    run_action_interactive(terminal, app, &[update.backend])
}

fn open_modal(app: &mut App, action: InputAction, title: &str, help: &str, initial: &str) {
    app.modal = Some(InputModal {
        title: title.to_string(),
        help: help.to_string(),
        action,
        value: initial.to_string(),
        changed_files: Vec::new(),
    });
}

fn open_apply_commit_modal(app: &mut App, entries: &[GitStatusEntry]) {
    app.modal = Some(InputModal {
        title: "Commit Changes Before Apply".to_string(),
        help: "Uncommitted Maestro files must be committed before applying. Enter a commit message, or leave it blank to auto-generate one from today's date and the changed files.".to_string(),
        action: InputAction::CommitAndApplyConfiguration,
        value: String::new(),
        changed_files: entries.iter().map(format_status_entry).collect(),
    });
}

fn run_apply_configuration(terminal: &mut AppTerminal, app: &mut App) -> Result<()> {
    let changes = uncommitted_config_files(&app.repo_root)?;
    if !changes.is_empty() {
        open_apply_commit_modal(app, &changes);
        return Ok(());
    }

    run_apply_command(terminal, app)
}

fn run_apply_command(terminal: &mut AppTerminal, app: &mut App) -> Result<()> {
    run_command_interactive(terminal, app, "Apply Configuration", {
        let mut command = Command::new(app.repo_root.join("modules/features/operator/cli/_source/maestroctl.sh"));
        command.arg("apply");
        command
    })
}

fn run_rollback_generation(terminal: &mut AppTerminal, app: &mut App) -> Result<()> {
    run_command_interactive(terminal, app, "Rollback Generation", {
        let mut command = Command::new(app.repo_root.join("modules/features/operator/cli/_source/maestroctl.sh"));
        command.arg("rollback");
        command
    })
}

fn run_garbage_collection(terminal: &mut AppTerminal, app: &mut App) -> Result<()> {
    run_command_interactive(terminal, app, "Run Garbage Collection", {
        let mut command = nh_command();
        command.args(["clean", "all", "--ask"]);
        command.args(["--elevation-strategy", sudo_program()]);
        command
    })
}

fn run_reboot_system(terminal: &mut AppTerminal, app: &mut App) -> Result<()> {
    run_command_interactive(terminal, app, "Reboot System", {
        let mut command = sudo_command();
        command.args(["systemctl", "reboot"]);
        command
    })
}

fn run_shutdown_system(terminal: &mut AppTerminal, app: &mut App) -> Result<()> {
    run_command_interactive(terminal, app, "Shut Down System", {
        let mut command = sudo_command();
        command.args(["systemctl", "poweroff"]);
        command
    })
}

fn run_action_capture(app: &mut App, args: &[&str]) -> Result<()> {
    let output = backend_action(&app.repo_root, args)
        .with_context(|| format!("failed to run backend action {}", args.join(" ")))?;
    let success = output.status.success();
    let rendered = render_output(&output);

    if rendered.is_empty() {
        app.push_log(format!("Action `{}` completed.", args.join(" ")));
    } else {
        for line in rendered.lines() {
            app.push_log(line.to_string());
        }
    }

    app.refresh_snapshot()?;
    app.start_update_check();

    if !success {
        app.push_log(format!(
            "Action `{}` exited with status {}.",
            args.join(" "),
            output.status
        ));
    }

    Ok(())
}

fn run_action_interactive(terminal: &mut AppTerminal, app: &mut App, args: &[&str]) -> Result<()> {
    let mut command = Command::new(app.repo_root.join("modules/features/operator/menu/_source/backend/action.sh"));
    command.args(args).env("MAESTRO_SYSTEM_ROOT", &app.repo_root);
    run_command_interactive(
        terminal,
        app,
        format!("Interactive action `{}`", args.join(" ")),
        command,
    )
}

fn backend_action(repo_root: &Path, args: &[&str]) -> Result<Output> {
    Command::new(repo_root.join("modules/features/operator/menu/_source/backend/action.sh"))
        .args(args)
        .env("MAESTRO_SYSTEM_ROOT", repo_root)
        .output()
        .with_context(|| {
            format!(
                "failed to execute {}",
                repo_root.join("modules/features/operator/menu/_source/backend/action.sh").display()
            )
        })
}

fn run_command_interactive(
    terminal: &mut AppTerminal,
    app: &mut App,
    label: impl Into<String>,
    mut command: Command,
) -> Result<()> {
    let label = label.into();
    command.env("MAESTRO_SYSTEM_ROOT", &app.repo_root);

    suspend_terminal(terminal)?;
    let status_result = command.status();
    let resume_result = resume_terminal(terminal);
    let status =
        status_result.with_context(|| format!("failed to run interactive command for {label}"))?;
    resume_result?;

    if status.success() {
        app.push_log(format!("{label} completed successfully."));
    } else {
        app.push_log(format!("{label} failed with status {status}."));
    }

    app.refresh_snapshot()?;
    app.start_update_check();

    Ok(())
}

fn uncommitted_config_files(repo_root: &Path) -> Result<Vec<GitStatusEntry>> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo_root)
        .args(["status", "--short", "--"])
        .args(TRACKED_PATHS);

    let output = command
        .output()
        .context("failed to inspect uncommitted Maestro files")?;

    if !output.status.success() {
        return Err(anyhow!(
            "git status failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_status_entry)
        .collect())
}

fn parse_status_entry(line: &str) -> Option<GitStatusEntry> {
    if line.trim().is_empty() {
        return None;
    }

    let status = line.chars().take(2).collect::<String>();
    let path = line.chars().skip(3).collect::<String>();
    if path.trim().is_empty() {
        return None;
    }

    Some(GitStatusEntry { status, path })
}

fn format_status_entry(entry: &GitStatusEntry) -> String {
    format!("{} {}", entry.status, entry.path)
}

fn commit_uncommitted_changes(app: &mut App, message: &str) -> Result<bool> {
    let entries = uncommitted_config_files(&app.repo_root)?;
    if entries.is_empty() {
        app.push_log("No uncommitted Maestro files were found before apply.");
        return Ok(true);
    }

    let commit_message = if message.trim().is_empty() {
        autogenerated_commit_message(&entries)
    } else {
        message.trim().to_string()
    };

    let output = Command::new(app.repo_root.join("modules/features/operator/cli/_source/maestroctl.sh"))
        .arg("commit")
        .arg(commit_message)
        .env("MAESTRO_SYSTEM_ROOT", &app.repo_root)
        .output()
        .with_context(|| {
            format!(
                "failed to run {}",
                app.repo_root.join("modules/features/operator/cli/_source/maestroctl.sh").display()
            )
        })?;

    let rendered = render_output(&output);
    if rendered.is_empty() {
        app.push_log("Commit helper completed without output.");
    } else {
        for line in rendered.lines() {
            app.push_log(line.to_string());
        }
    }

    app.refresh_snapshot()?;
    app.start_update_check();

    if output.status.success() {
        Ok(true)
    } else {
        app.push_log(format!(
            "Commit helper failed with status {}; apply was not started.",
            output.status
        ));
        Ok(false)
    }
}

fn autogenerated_commit_message(entries: &[GitStatusEntry]) -> String {
    let date = current_date_utc();
    let files = entries
        .iter()
        .map(|entry| format!("- {}", entry.path))
        .collect::<Vec<_>>()
        .join("\n");

    format!("Save Maestro changes on {date}\n\nChanged files:\n{files}")
}

fn current_date_utc() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%d"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown date".to_string())
}

fn render_output(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout,
        (true, false) => stderr,
        (false, false) => format!("{stdout}\n{stderr}"),
    }
}

fn format_gib(bytes: u64) -> f64 {
    bytes as f64 / 1024.0 / 1024.0 / 1024.0
}

fn short_sha(value: &str) -> String {
    value.chars().take(8).collect()
}

fn format_usage(used_bytes: u64, total_bytes: u64, percent: u32) -> String {
    if total_bytes == 0 {
        "unavailable".to_string()
    } else {
        format!(
            "{:.1} / {:.1} GiB ({}%)",
            format_gib(used_bytes),
            format_gib(total_bytes),
            percent
        )
    }
}

fn usage_color(percent: u32) -> Color {
    if percent >= 90 {
        COLOR_DANGER
    } else if percent >= 75 {
        COLOR_WARNING
    } else {
        COLOR_SUCCESS
    }
}

fn repo_status(snapshot: &Snapshot) -> (String, Color) {
    if snapshot.dirty_count == 0 {
        ("clean".to_string(), COLOR_SUCCESS)
    } else {
        (format!("{} dirty", snapshot.dirty_count), COLOR_WARNING)
    }
}

fn apply_status(snapshot: &Snapshot) -> (String, Color) {
    if snapshot.rebuild_queued {
        ("queued for reboot".to_string(), COLOR_INFO)
    } else {
        match &snapshot.last_apply {
            Some(last_apply)
                if last_apply.result == "success"
                    && last_apply.action == "switch"
                    && !snapshot.rebuild_needed =>
            {
                (format!("synced {}", last_apply.timestamp), COLOR_SUCCESS)
            }
            Some(last_apply) if last_apply.result != "success" => {
                (format!("failed {}", last_apply.timestamp), COLOR_DANGER)
            }
            Some(last_apply) => (
                format!("{} {}", last_apply.action, last_apply.timestamp),
                COLOR_WARNING,
            ),
            None => ("not applied".to_string(), COLOR_WARNING),
        }
    }
}

fn upstream_status(snapshot: &Snapshot) -> (String, Color) {
    if snapshot.behind > 0 {
        (
            format!("behind {} / ahead {}", snapshot.behind, snapshot.ahead),
            COLOR_WARNING,
        )
    } else if snapshot.ahead > 0 {
        (format!("ahead {}", snapshot.ahead), COLOR_INFO)
    } else {
        ("aligned".to_string(), COLOR_SUCCESS)
    }
}

fn inputs_status(update_status: &UpdateStatus, tick: usize) -> (String, Color) {
    match update_status {
        UpdateStatus::Idle => ("idle".to_string(), COLOR_MUTED_2),
        UpdateStatus::Checking => {
            let frames = ["-", "\\", "|", "/"];
            (
                format!("checking {}", frames[tick % frames.len()]),
                COLOR_INFO,
            )
        }
        UpdateStatus::UpToDate => ("up to date".to_string(), COLOR_SUCCESS),
        UpdateStatus::Available(count) => (format!("{count} updates"), COLOR_WARNING),
        UpdateStatus::Error(_) => ("check failed".to_string(), COLOR_DANGER),
    }
}

fn xoa_version(snapshot: &Snapshot) -> String {
    snapshot
        .xen_orchestra_version
        .clone()
        .unwrap_or_else(|| "unavailable".to_string())
}

fn web_ui(snapshot: &Snapshot) -> String {
    snapshot
        .web_ui_url
        .clone()
        .or_else(|| snapshot.primary_ip.clone())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn format_storage_capacity(used_bytes: u64, total_bytes: u64) -> String {
    if total_bytes == 0 || used_bytes > total_bytes {
        "unavailable".to_string()
    } else {
        format!(
            "{:.1} / {:.1}",
            format_gib(used_bytes),
            format_gib(total_bytes)
        )
    }
}

#[derive(Clone, Copy)]
enum PanelTone {
    Neutral,
    Info,
    Warning,
}

fn panel_color(tone: PanelTone, focused: bool) -> Color {
    if focused {
        COLOR_ACCENT
    } else {
        match tone {
            PanelTone::Neutral => COLOR_BORDER_DIM,
            PanelTone::Info | PanelTone::Warning => COLOR_BORDER_MID,
        }
    }
}

fn panel_block(title: impl Into<String>, focused: bool, tone: PanelTone) -> Block<'static> {
    let title = title.into();
    let title_style = if focused {
        Style::default()
            .fg(panel_color(tone, focused))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(COLOR_FG_MAIN)
            .add_modifier(Modifier::BOLD)
    };

    Block::default()
        .title(
            Line::from(if focused {
                format!(" ● {title} ")
            } else {
                format!(" {title} ")
            })
            .style(title_style),
        )
        .borders(Borders::ALL)
        .border_set(border::ROUNDED)
        .border_style(
            Style::default()
                .fg(panel_color(tone, focused))
                .add_modifier(if focused {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        )
        .border_type(BorderType::Rounded)
        .style(Style::default().bg(if focused {
            COLOR_BG_FOCUSED
        } else {
            COLOR_BG_INNER
        }))
}

fn inset_rect(area: Rect, x: u16, y: u16) -> Rect {
    let width = area.width.saturating_sub(x.saturating_mul(2));
    let height = area.height.saturating_sub(y.saturating_mul(2));
    Rect {
        x: area.x.saturating_add(x),
        y: area.y.saturating_add(y),
        width,
        height,
    }
}

fn draw_panel(
    frame: &mut Frame,
    area: Rect,
    title: impl Into<String>,
    focused: bool,
    tone: PanelTone,
) -> Rect {
    let block = panel_block(title, focused, tone);
    let inner = inset_rect(block.inner(area), 1, 0);
    frame.render_widget(block, area);
    inner
}

fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(COLOR_BG_OUTER)),
        area,
    );

    let outer = inset_rect(area, 1, 1);
    if outer.width < 80 || outer.height < 22 {
        render_too_small(frame, outer, app);
        if let Some(modal) = &app.modal {
            render_input_modal(frame, outer, modal);
        }
        if let Some(_) = &app.command_palette {
            render_command_palette(frame, outer, app);
        }
        if app.help_open {
            render_help_modal(frame, outer, app);
        }
        if app.quit_confirm {
            render_quit_confirm(frame, outer, app);
        }
        return;
    }

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(outer);

    render_header(frame, vertical[0], app);

    let body = if outer.width >= 120 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(34),
                Constraint::Length(1),
                Constraint::Min(40),
            ])
            .split(vertical[1])
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(30),
                Constraint::Length(1),
                Constraint::Min(30),
            ])
            .split(vertical[1])
    };

    let sidebar_area = body[0];
    let page_area = body[2];

    render_sidebar(frame, inset_rect(sidebar_area, 0, 0), app);
    render_page(frame, inset_rect(page_area, 0, 0), app);
    render_footer(frame, vertical[2], app);

    if let Some(modal) = &app.modal {
        render_input_modal(frame, outer, modal);
    }
    if app.command_palette.is_some() {
        render_command_palette(frame, outer, app);
    }
    if app.help_open {
        render_help_modal(frame, outer, app);
    }
    if app.quit_confirm {
        render_quit_confirm(frame, outer, app);
    }
}

fn render_too_small(frame: &mut Frame, area: Rect, app: &App) {
    let inner = draw_panel(frame, area, "Maestro Console", true, PanelTone::Info);
    let text = vec![
        Line::from(vec![
            Span::styled("Host: ", Style::default().fg(COLOR_MUTED_2)),
            Span::styled(
                format!("{}@{}", app.snapshot.username, app.snapshot.hostname),
                Style::default().fg(COLOR_FG_MAIN),
            ),
        ]),
        Line::from(vec![
            Span::styled("Page: ", Style::default().fg(COLOR_MUTED_2)),
            Span::styled(app.page_title(), Style::default().fg(COLOR_ACCENT)),
        ]),
        Line::from(""),
        Line::from("Increase terminal size for the full multi-pane console."),
        Line::from("Esc unwinds to the main menu. Esc there prompts to return to shell."),
    ];

    let paragraph = Paragraph::new(text)
        .style(Style::default().bg(COLOR_BG_INNER).fg(COLOR_FG_MAIN))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, inner);
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let inner = draw_panel(frame, area, "", false, PanelTone::Info);
    let upstream = app
        .snapshot
        .upstream
        .clone()
        .unwrap_or_else(|| "no upstream".to_string());
    let (repo_text, repo_color) = repo_status(&app.snapshot);
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(32),
            Constraint::Percentage(34),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(vec![
            header_key_value_line(
                "Host",
                &format!("{}@{}", app.snapshot.username, app.snapshot.hostname),
                COLOR_ACCENT,
            ),
            header_key_value_line("Focus", focus_label(app.focus), COLOR_FG_MAIN),
        ]),
        columns[0],
    );

    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "NiXO-CE",
                Style::default()
                    .fg(COLOR_FG_MAIN)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                app.page_title(),
                Style::default().fg(COLOR_ACCENT),
            )),
        ])
        .alignment(Alignment::Center),
        columns[1],
    );

    frame.render_widget(
        Paragraph::new(vec![
            header_key_value_line(
                "Branch",
                &format!(
                    "{} [{}]",
                    app.snapshot.branch,
                    short_sha(&app.snapshot.head)
                ),
                COLOR_FG_MAIN,
            ),
            Line::from(vec![
                Span::styled(
                    format!("{:<width$}", "Upstream", width = HEADER_LABEL_WIDTH),
                    Style::default().fg(COLOR_MUTED_2),
                ),
                Span::raw("  "),
                Span::styled(truncate_end(&upstream, 20), Style::default().fg(COLOR_INFO)),
                Span::raw("  "),
                Span::styled(repo_text, Style::default().fg(repo_color)),
            ]),
        ])
        .alignment(Alignment::Right)
        .wrap(Wrap { trim: true }),
        columns[2],
    );
}

fn render_sidebar(frame: &mut Frame, area: Rect, app: &App) {
    if app.focus_is(Focus::PrimaryMenu) {
        render_primary_sidebar(frame, area, app);
    } else {
        render_options_sidebar(frame, area, app);
    }
}

fn render_primary_sidebar(frame: &mut Frame, area: Rect, app: &App) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(8)])
        .split(area);

    let primary_inner = draw_panel(
        frame,
        sections[0],
        "Main Menu",
        app.focus_is(Focus::PrimaryMenu),
        PanelTone::Neutral,
    );

    let primary_items: Vec<ListItem> = primary_pages()
        .iter()
        .map(|page| {
            let prefix = if *page == app.page { ">" } else { " " };
            ListItem::new(Line::from(vec![
                Span::styled(prefix, Style::default().fg(COLOR_ACCENT)),
                Span::raw(" "),
                Span::styled("  ", Style::default().fg(COLOR_MUTED_2)),
                Span::styled(page_label(*page), Style::default().fg(COLOR_FG_MAIN)),
            ]))
        })
        .collect();

    let mut primary_state = ListState::default();
    primary_state.select(Some(App::page_index(app.page)));
    let primary_list = List::new(primary_items).highlight_style(
        Style::default()
            .bg(COLOR_ACCENT_SOFT)
            .fg(COLOR_FG_MAIN)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_stateful_widget(primary_list, primary_inner, &mut primary_state);

    let detail_inner = draw_panel(frame, sections[1], "Section", false, PanelTone::Neutral);
    let detail = Paragraph::new(vec![
        Line::from(Span::styled(
            app.page_title(),
            Style::default()
                .fg(COLOR_FG_MAIN)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            primary_page_detail(app.page),
            Style::default().fg(COLOR_MUTED),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Enter ", Style::default().fg(COLOR_ACCENT)),
            Span::styled("open submenu", Style::default().fg(COLOR_MUTED_2)),
        ]),
        Line::from(vec![
            Span::styled("Esc ", Style::default().fg(COLOR_ACCENT)),
            Span::styled("return to shell prompt", Style::default().fg(COLOR_MUTED_2)),
        ]),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(detail, detail_inner);
}

fn render_options_sidebar(frame: &mut Frame, area: Rect, app: &App) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(9)])
        .split(area);

    let option_inner = draw_panel(
        frame,
        sections[0],
        format!("{} Options", app.page_title()),
        true,
        PanelTone::Neutral,
    );

    let options = app.menu_options();
    let items: Vec<ListItem> = options
        .iter()
        .map(|option| {
            let (label, meta) = option_label(app, *option);
            ListItem::new(Line::from(vec![
                Span::styled(meta, Style::default().fg(COLOR_MUTED_2)),
                Span::styled(label, Style::default().fg(COLOR_FG_MAIN)),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(app.current_selection()));
    }
    let list = List::new(items).highlight_style(
        Style::default()
            .bg(COLOR_ACCENT_SOFT)
            .fg(COLOR_FG_MAIN)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_stateful_widget(list, option_inner, &mut state);

    let detail_inner = draw_panel(frame, sections[1], "Selection", false, PanelTone::Neutral);
    let detail_width = detail_inner.width.saturating_sub(1) as usize;
    let title = app.selected_sidebar_title();
    let detail_text = app.selected_sidebar_detail();
    let detail = Paragraph::new(vec![
        Line::from(Span::styled(
            title,
            Style::default()
                .fg(COLOR_FG_MAIN)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            truncate_end(&detail_text, detail_width.saturating_mul(3)),
            Style::default().fg(COLOR_MUTED),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Enter ", Style::default().fg(COLOR_ACCENT)),
            Span::styled("advance or run", Style::default().fg(COLOR_MUTED_2)),
        ]),
        Line::from(vec![
            Span::styled("Esc ", Style::default().fg(COLOR_ACCENT)),
            Span::styled("back / shell prompt", Style::default().fg(COLOR_MUTED_2)),
        ]),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(detail, detail_inner);
}

fn render_page(frame: &mut Frame, area: Rect, app: &App) {
    match app.page {
        Page::Status => render_status(frame, area, app),
        Page::HostSetup => render_host_setup(frame, area, app),
        Page::Access => render_access(frame, area, app),
        Page::Packages => render_packages(frame, area, app),
        Page::Updates => render_updates(frame, area, app),
        Page::Maintenance => render_maintenance(frame, area, app),
        Page::Logs => render_logs_page(frame, area, app),
        Page::Shell => render_shell_page(frame, area),
    }
}

fn render_status(frame: &mut Frame, area: Rect, app: &App) {
    let alert_count = app.alerts().len() as u16;
    let alert_height = (alert_count.saturating_add(3)).clamp(4, 7);
    let top_height = if area.height >= 20 { 10 } else { 9 };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(top_height),
            Constraint::Length(alert_height),
            Constraint::Min(6),
        ])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(57), Constraint::Percentage(43)])
        .split(rows[0]);

    render_system_summary(frame, top[0], app);
    render_repository_status(frame, top[1], app);
    render_alerts(frame, rows[1], app);
    render_recent_activity(frame, rows[2], app);
}

fn render_system_summary(frame: &mut Frame, area: Rect, app: &App) {
    let inner = draw_panel(frame, area, "System Summary", false, PanelTone::Info);

    let content = Paragraph::new(vec![
        key_value_line("Hostname", &app.snapshot.hostname, COLOR_ACCENT),
        key_value_line("Username", &app.snapshot.username, COLOR_FG_MAIN),
        key_value_line("XOA", &xoa_version(&app.snapshot), COLOR_FG_MAIN),
        key_value_line("Web UI", &web_ui(&app.snapshot), COLOR_FG_MAIN),
        key_value_line(
            "RAM",
            &format_usage(
                app.snapshot.memory_used_bytes,
                app.snapshot.memory_total_bytes,
                app.snapshot.memory_used_percent,
            ),
            usage_color(app.snapshot.memory_used_percent),
        ),
        key_value_line(
            "Storage",
            &format_storage_capacity(
                app.snapshot.storage_used_bytes,
                app.snapshot.storage_total_bytes,
            ),
            usage_color(app.snapshot.storage_used_percent),
        ),
        key_value_line("Time zone", &app.snapshot.timezone, COLOR_FG_MAIN),
        key_value_line(
            "Extras",
            if app.snapshot.extras {
                "enabled"
            } else {
                "disabled"
            },
            if app.snapshot.extras {
                COLOR_SUCCESS
            } else {
                COLOR_WARNING
            },
        ),
        key_value_line(
            "Development Mode",
            if app.snapshot.development_mode {
                "enabled"
            } else {
                "disabled"
            },
            if app.snapshot.development_mode {
                COLOR_SUCCESS
            } else {
                COLOR_WARNING
            },
        ),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(content, inner);
}

fn render_repository_status(frame: &mut Frame, area: Rect, app: &App) {
    let inner = draw_panel(frame, area, "Repository Status", false, PanelTone::Neutral);
    let (repo_text, repo_color) = repo_status(&app.snapshot);
    let (apply_text, apply_color) = apply_status(&app.snapshot);
    let (upstream_text, upstream_color) = upstream_status(&app.snapshot);
    let (inputs_text, inputs_color) = inputs_status(&app.update_status, app.tick);

    let content = Paragraph::new(vec![
        key_value_line(
            "Branch",
            &format!(
                "{} [{}]",
                app.snapshot.branch,
                short_sha(&app.snapshot.head)
            ),
            COLOR_FG_MAIN,
        ),
        key_value_line("Repository Status", &repo_text, repo_color),
        key_value_line("Apply Status", &apply_text, apply_color),
        key_value_line("Upstream", &upstream_text, upstream_color),
        key_value_line("Flake Inputs", &inputs_text, inputs_color),
        key_value_line(
            "SSH Keys",
            &app.snapshot.ssh_keys.len().to_string(),
            COLOR_FG_MAIN,
        ),
        key_value_line(
            "Packages",
            &format!(
                "{} system / {} user",
                app.snapshot.system_packages.len(),
                app.snapshot.user_packages.len()
            ),
            COLOR_FG_MAIN,
        ),
        key_value_line(
            "Services",
            &app.snapshot.services.len().to_string(),
            COLOR_FG_MAIN,
        ),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(content, inner);
}

fn render_alerts(frame: &mut Frame, area: Rect, app: &App) {
    let inner = draw_panel(frame, area, "Alerts", false, PanelTone::Warning);

    let alerts = app.alerts();
    let items: Vec<ListItem> = alerts
        .iter()
        .map(|alert| {
            let badge = match alert.severity {
                Severity::Info => ("INFO", COLOR_INFO),
                Severity::Warning => ("WARN", COLOR_WARNING),
                Severity::Error => ("ERROR", COLOR_DANGER),
            };

            let mut spans = vec![
                Span::styled(
                    format!("[{}] ", badge.0),
                    Style::default().fg(badge.1).add_modifier(Modifier::BOLD),
                ),
                Span::styled(alert.message.clone(), Style::default().fg(COLOR_FG_MAIN)),
            ];

            if let Some(label) = alert.action_label {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(
                    format!("({label})"),
                    Style::default().fg(COLOR_ACCENT),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default();
    if !alerts.is_empty() {
        state.select(Some(app.selected_alert));
    }

    let list = List::new(items).highlight_style(
        Style::default()
            .bg(COLOR_ACCENT_SOFT)
            .fg(COLOR_FG_MAIN)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_stateful_widget(list, inner, &mut state);
}

fn render_recent_activity(frame: &mut Frame, area: Rect, app: &App) {
    let inner = draw_panel(frame, area, "Recent Activity", false, PanelTone::Neutral);
    let max_width = inner.width.saturating_sub(1) as usize;
    let max_lines = max(inner.height as usize, 1);
    let lines: Vec<Line> = app
        .filtered_logs()
        .into_iter()
        .take(max_lines)
        .map(|line| Line::from(truncate_end(&line, max_width)))
        .collect();
    let paragraph = Paragraph::new(Text::from(lines));
    frame.render_widget(paragraph, inner);
}

fn render_host_setup(frame: &mut Frame, area: Rect, app: &App) {
    let action = app
        .selected_page_action()
        .map(|item| item.kind)
        .unwrap_or(ActionKind::ToggleExtras);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(6)])
        .split(area);

    let summary_inner = draw_panel(frame, rows[0], "Host Setup", false, PanelTone::Info);
    let summary = Paragraph::new(vec![
        key_value_line("Hostname", &app.snapshot.hostname, COLOR_ACCENT),
        key_value_line("Username", &app.snapshot.username, COLOR_FG_MAIN),
        key_value_line(
            "Extras",
            if app.snapshot.extras {
                "enabled"
            } else {
                "disabled"
            },
            if app.snapshot.extras {
                COLOR_SUCCESS
            } else {
                COLOR_WARNING
            },
        ),
        key_value_line(
            "Development Mode",
            if app.snapshot.development_mode {
                "enabled"
            } else {
                "disabled"
            },
            if app.snapshot.development_mode {
                COLOR_SUCCESS
            } else {
                COLOR_WARNING
            },
        ),
        key_value_line("Time zone", &app.snapshot.timezone, COLOR_FG_MAIN),
        Line::from("Host setup actions write console overrides and commit the change immediately."),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(summary, summary_inner);

    match action {
        ActionKind::ToggleExtras => render_simple_detail(
            frame,
            rows[1],
            "Selected Action",
            &[
                format!(
                    "Extras are currently {}.",
                    if app.snapshot.extras {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ),
                "Enter toggles the extras feature set and commits the override.".to_string(),
            ],
            false,
            PanelTone::Info,
        ),
        ActionKind::ToggleDevelopmentMode => render_simple_detail(
            frame,
            rows[1],
            "Selected Action",
            &[
                format!(
                    "Development Mode is currently {}.",
                    if app.snapshot.development_mode {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ),
                "Enter toggles devenv, Rust, Node.js, and Redis/Valkey helper tooling.".to_string(),
            ],
            false,
            PanelTone::Info,
        ),
        _ => {}
    }
}

fn render_access(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(8)])
        .split(area);

    let summary_inner = draw_panel(frame, rows[0], "Access", false, PanelTone::Info);
    let selected_key = app.snapshot.ssh_keys.get(app.selected_key);
    let summary = Paragraph::new(vec![
        key_value_line(
            "SSH Keys",
            &app.snapshot.ssh_keys.len().to_string(),
            COLOR_FG_MAIN,
        ),
        key_value_line(
            "Selected",
            selected_key
                .map(|key| truncate_middle(key, 54))
                .unwrap_or_else(|| "none".to_string())
                .as_str(),
            if selected_key.is_some() {
                COLOR_ACCENT
            } else {
                COLOR_MUTED
            },
        ),
        Line::from("Key entries live in the Access submenu below the access actions."),
        Line::from("Successful key changes commit only host/menu.nix."),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(summary, summary_inner);

    let option = app.selected_menu_option();
    let lines = if let Some(MenuOption::SshKey(index)) = option {
        vec![
            format!("Selected key: {}", index + 1),
            app.snapshot
                .ssh_keys
                .get(index)
                .cloned()
                .unwrap_or_else(|| "No key selected.".to_string()),
            "Use Delete Selected Key from the Access submenu to remove this key.".to_string(),
        ]
    } else {
        vec![
            app.selected_sidebar_title(),
            app.selected_sidebar_detail(),
            "Enter runs the selected access action.".to_string(),
        ]
    };

    render_simple_detail(frame, rows[1], "Details", &lines, false, PanelTone::Neutral);
}

fn render_packages(frame: &mut Frame, area: Rect, app: &App) {
    let action = app
        .selected_page_action()
        .map(|item| item.kind)
        .unwrap_or(ActionKind::AddSystemPackage);

    match action {
        ActionKind::AddSystemPackage => render_item_list_page(
            frame,
            area,
            "System Packages",
            &app.snapshot.system_packages,
            "Press Enter to add a new nixpkgs attribute path to the system package list.",
            false,
            false,
        ),
        ActionKind::AddUserPackage => render_item_list_page(
            frame,
            area,
            "User Packages",
            &app.snapshot.user_packages,
            "Press Enter to add a new nixpkgs attribute path to the user package list.",
            false,
            false,
        ),
        ActionKind::AddService => render_item_list_page(
            frame,
            area,
            "Services",
            &app.snapshot.services,
            "Press Enter to enable a service by dotted NixOS option path.",
            false,
            false,
        ),
        _ => {}
    }
}

fn render_maintenance(frame: &mut Frame, area: Rect, app: &App) {
    match app
        .selected_page_action()
        .map(|item| item.kind)
        .unwrap_or(ActionKind::ApplyConfiguration)
    {
        ActionKind::ApplyConfiguration => render_maintenance_detail_page(
            frame,
            area,
            "Apply Configuration",
            "Apply the current repository state to this host.",
            "The active host configuration is rebuilt from the current flake and switched in after the command exits.",
            "Applying configuration changes the running system state immediately. Review the current build status before proceeding.",
            "Enter runs maestroctl apply for this host.",
            app,
        ),
        ActionKind::RollbackGeneration => render_maintenance_detail_page(
            frame,
            area,
            "Rollback Generation",
            "Restore the previous NixOS generation for this host.",
            "Use this when the last switch introduced a regression and the prior generation should be made active again.",
            "Rollback changes the running system state. Confirm that the previous generation is the one you want to restore.",
            "Enter runs maestroctl rollback for .#maestro.",
            app,
        ),
        ActionKind::RunGarbageCollection => render_maintenance_detail_page(
            frame,
            area,
            "Run Garbage Collection",
            "Delete old generations and unreachable store paths.",
            "This reclaims disk space and reduces retained history in the Nix store.",
            "Garbage collection is destructive. It may remove rollback targets you still expect to use later.",
            "Enter runs nh clean all --ask.",
            app,
        ),
        ActionKind::RebootSystem => render_maintenance_detail_page(
            frame,
            area,
            "Reboot System",
            "Request a clean reboot through systemd.",
            "Use this after changes that should apply on the next boot or when the appliance needs a restart.",
            "Reboot interrupts active sessions and workloads running on the host.",
            "Enter runs systemctl reboot.",
            app,
        ),
        ActionKind::ShutdownSystem => render_maintenance_detail_page(
            frame,
            area,
            "Shut Down System",
            "Request a clean poweroff through systemd.",
            "Use this when the appliance should be taken offline in a controlled way.",
            "Shutdown powers the machine off and ends every active session immediately.",
            "Enter runs systemctl poweroff.",
            app,
        ),
        ActionKind::CleanupUnmanagedUsers => render_maintenance_detail_page(
            frame,
            area,
            "Cleanup Unmanaged Users",
            "Remove unmanaged non-system users from this host.",
            "The cleanup deletes those users and removes their home directories under /home.",
            "This is irreversible for the affected users and their data. Use it only when the host should be fully re-aligned with the flake.",
            "Enter opens a WIPE confirmation prompt.",
            app,
        ),
        _ => {}
    }
}

fn render_updates(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(8)])
        .split(area);

    let status_inner = draw_panel(frame, rows[0], "Flake Input Status", false, PanelTone::Info);
    let (inputs_text, inputs_color) = inputs_status(&app.update_status, app.tick);
    let status = Paragraph::new(vec![
        key_value_line("Input status", &inputs_text, inputs_color),
        key_value_line(
            "Queued on boot",
            if app.snapshot.rebuild_queued {
                "yes"
            } else {
                "no"
            },
            if app.snapshot.rebuild_queued {
                COLOR_INFO
            } else {
                COLOR_FG_MAIN
            },
        ),
        key_value_line(
            "Needs rebuild",
            if app.snapshot.rebuild_needed {
                "yes"
            } else {
                "no"
            },
            if app.snapshot.rebuild_needed {
                COLOR_WARNING
            } else {
                COLOR_FG_MAIN
            },
        ),
        Line::from("Update targets are selected from the Updates submenu."),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(status, status_inner);

    let detail_inner = draw_panel(frame, rows[1], "Selected Target", false, PanelTone::Neutral);
    let update = &UPDATE_ACTIONS[app.selected_update];
    let content = Paragraph::new(vec![
        Line::from(Span::styled(
            update.title,
            Style::default()
                .fg(COLOR_FG_MAIN)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(update.detail),
        Line::from(""),
        Line::from("Each update commits only flake.lock."),
        Line::from(
            "After a lock change, the backend asks whether to rebuild now or on the next boot.",
        ),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(content, detail_inner);
}

fn render_logs_page(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(8)])
        .split(area);

    let meta_inner = draw_panel(frame, rows[0], "Recent Activity", false, PanelTone::Neutral);
    let filtered_logs = app.filtered_logs();
    let meta = Paragraph::new(vec![
        key_value_line(
            "Filter",
            if app.log_filter.is_empty() {
                "none"
            } else {
                app.log_filter.as_str()
            },
            if app.log_filter.is_empty() {
                COLOR_MUTED
            } else {
                COLOR_ACCENT
            },
        ),
        key_value_line(
            "Visible entries",
            &filtered_logs.len().to_string(),
            COLOR_FG_MAIN,
        ),
        Line::from("Use the Logs submenu to filter, clear, and scroll the preview."),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(meta, meta_inner);

    let log_inner = draw_panel(frame, rows[1], "Logs", false, PanelTone::Info);
    if filtered_logs.is_empty() {
        frame.render_widget(
            Paragraph::new("No log entries matched the current filter.").wrap(Wrap { trim: true }),
            log_inner,
        );
        return;
    }

    let visible_height = max(log_inner.height as usize, 1);
    let scroll = min(app.log_scroll, filtered_logs.len().saturating_sub(1));
    let start = scroll;
    let end = min(start + visible_height, filtered_logs.len());
    let lines: Vec<Line> = filtered_logs[start..end]
        .iter()
        .map(|line| Line::from(line.clone()))
        .collect();

    let paragraph = Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, log_inner);
}

fn render_shell_page(frame: &mut Frame, area: Rect) {
    render_simple_detail(
        frame,
        area,
        "Shell",
        &[
            "Return to the configured login shell.".to_string(),
            "The shell is started with MAESTRO_TUI_BYPASS=1 so the console does not restart immediately.".to_string(),
            "Press Enter on Shell or Esc from the main menu to open the Y/N prompt.".to_string(),
        ],
        false,
        PanelTone::Info,
    );
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let inner = draw_panel(frame, area, "Shortcuts", false, PanelTone::Neutral);
    let (inputs_text, inputs_color) = inputs_status(&app.update_status, app.tick);
    let footer = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Up/Down ", Style::default().fg(COLOR_ACCENT)),
            Span::styled("choose", Style::default().fg(COLOR_MUTED)),
            Span::raw("   "),
            Span::styled("Enter ", Style::default().fg(COLOR_ACCENT)),
            Span::styled("advance or run", Style::default().fg(COLOR_MUTED)),
            Span::raw("   "),
            Span::styled("Esc ", Style::default().fg(COLOR_ACCENT)),
            Span::styled("back / shell prompt", Style::default().fg(COLOR_MUTED)),
            Span::raw("   "),
            Span::styled(": ", Style::default().fg(COLOR_ACCENT)),
            Span::styled("palette", Style::default().fg(COLOR_MUTED)),
            Span::raw("   "),
            Span::styled("? ", Style::default().fg(COLOR_ACCENT)),
            Span::styled("help", Style::default().fg(COLOR_MUTED)),
        ]),
        Line::from(vec![
            Span::styled("Inputs: ", Style::default().fg(COLOR_MUTED_2)),
            Span::styled(inputs_text, Style::default().fg(inputs_color)),
            Span::raw("   "),
            Span::styled("Last apply: ", Style::default().fg(COLOR_MUTED_2)),
            Span::styled(
                last_apply_label(&app.snapshot),
                Style::default().fg(COLOR_MUTED),
            ),
        ]),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(footer, inner);
}

fn render_simple_detail(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines: &[String],
    focused: bool,
    tone: PanelTone,
) {
    let inner = draw_panel(frame, area, title, focused, tone);
    let paragraph = Paragraph::new(lines.iter().cloned().map(Line::from).collect::<Vec<_>>())
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, inner);
}

fn render_maintenance_detail_page(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    summary: &str,
    outcome: &str,
    risk: &str,
    action_hint: &str,
    app: &App,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(8)])
        .split(area);

    let summary_inner = draw_panel(frame, rows[0], title, false, PanelTone::Neutral);
    let summary_text = Paragraph::new(vec![
        Line::from(Span::styled(summary, Style::default().fg(COLOR_FG_MAIN))),
        Line::from(Span::styled(outcome, Style::default().fg(COLOR_MUTED))),
        Line::from(Span::styled(action_hint, Style::default().fg(COLOR_ACCENT))),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(summary_text, summary_inner);

    let lower = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(rows[1]);

    let state_inner = draw_panel(frame, lower[0], "Current State", false, PanelTone::Neutral);
    let state = Paragraph::new(vec![
        key_value_line("Host", &app.snapshot.hostname, COLOR_FG_MAIN),
        key_value_line(
            "Queued on boot",
            if app.snapshot.rebuild_queued {
                "yes"
            } else {
                "no"
            },
            if app.snapshot.rebuild_queued {
                COLOR_INFO
            } else {
                COLOR_FG_MAIN
            },
        ),
        key_value_line(
            "Needs rebuild",
            if app.snapshot.rebuild_needed {
                "yes"
            } else {
                "no"
            },
            if app.snapshot.rebuild_needed {
                COLOR_WARNING
            } else {
                COLOR_FG_MAIN
            },
        ),
        key_value_line(
            "Inputs",
            &inputs_status(&app.update_status, app.tick).0,
            inputs_status(&app.update_status, app.tick).1,
        ),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(state, state_inner);

    let notes_inner = draw_panel(
        frame,
        lower[1],
        "Operational Notes",
        false,
        PanelTone::Neutral,
    );
    let notes = Paragraph::new(vec![
        Line::from(Span::styled(
            "Risk",
            Style::default()
                .fg(COLOR_DANGER)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(risk, Style::default().fg(COLOR_MUTED))),
        Line::from(""),
        Line::from(Span::styled("Use ?", Style::default().fg(COLOR_ACCENT))),
        Line::from(Span::styled(
            "for the full navigation reference and workflow help.",
            Style::default().fg(COLOR_MUTED),
        )),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(notes, notes_inner);
}

fn render_item_list_page(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    items: &[String],
    help: &str,
    list_focused: bool,
    details_focused: bool,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(5)])
        .split(area);

    let list_inner = draw_panel(frame, rows[0], title, list_focused, PanelTone::Info);
    let list_items: Vec<ListItem> = if items.is_empty() {
        vec![ListItem::new("No entries are currently configured.")]
    } else {
        items
            .iter()
            .map(|item| ListItem::new(truncate_middle(item, 100)))
            .collect()
    };
    frame.render_widget(List::new(list_items), list_inner);

    let help_inner = draw_panel(
        frame,
        rows[1],
        "Details",
        details_focused,
        PanelTone::Neutral,
    );
    frame.render_widget(Paragraph::new(help).wrap(Wrap { trim: true }), help_inner);
}

fn render_input_modal(frame: &mut Frame, area: Rect, modal: &InputModal) {
    let popup = centered_rect(
        if modal.changed_files.is_empty() {
            72
        } else {
            78
        },
        if modal.changed_files.is_empty() {
            32
        } else {
            54
        },
        area,
    );
    frame.render_widget(Clear, popup);
    let inner = draw_panel(frame, popup, modal.title.clone(), true, PanelTone::Info);
    let mut lines = vec![Line::from(modal.help.clone()), Line::from("")];

    if !modal.changed_files.is_empty() {
        lines.push(Line::from(Span::styled(
            "Uncommitted files",
            Style::default()
                .fg(COLOR_ACCENT)
                .add_modifier(Modifier::BOLD),
        )));
        let visible_limit = 9usize;
        for file in modal.changed_files.iter().take(visible_limit) {
            lines.push(Line::from(format!("  {file}")));
        }
        if modal.changed_files.len() > visible_limit {
            lines.push(Line::from(format!(
                "  ... and {} more",
                modal.changed_files.len() - visible_limit
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from("Commit message"));
    }

    lines.extend([
        Line::from(format!("> {}", modal.value)),
        Line::from(""),
        Line::from("Enter submits. Esc cancels. Ctrl+u clears the input."),
    ]);

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    frame.render_widget(paragraph, inner);
}

fn render_quit_confirm(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(48, 28, area);
    frame.render_widget(Clear, popup);
    let inner = draw_panel(frame, popup, "Return to Shell?", true, PanelTone::Info);
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(4),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(inner);

    let paragraph = Paragraph::new(vec![
        Line::from("Leave the console and exec the login shell?"),
        Line::from(""),
        Line::from("Use arrows and Enter, or press Y/N/Esc."),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, sections[0]);

    let choices = [ConfirmChoice::Yes, ConfirmChoice::No];
    let choice_items = choices
        .iter()
        .map(|choice| {
            let label = match choice {
                ConfirmChoice::Yes => "Yes",
                ConfirmChoice::No => "No",
            };
            ListItem::new(Line::from(Span::styled(
                label,
                Style::default().fg(COLOR_FG_MAIN),
            )))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default();
    state.select(Some(match app.quit_confirm_selection {
        ConfirmChoice::Yes => 0,
        ConfirmChoice::No => 1,
    }));
    let list = List::new(choice_items).highlight_style(
        Style::default()
            .bg(COLOR_ACCENT_SOFT)
            .fg(COLOR_FG_MAIN)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_stateful_widget(list, sections[1], &mut state);

    frame.render_widget(
        Paragraph::new("No keeps you in the console. Yes returns to the shell.")
            .style(Style::default().fg(COLOR_MUTED)),
        sections[2],
    );
}

fn render_command_palette(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(74, 62, area);
    frame.render_widget(Clear, popup);
    let inner = draw_panel(frame, popup, "Command Palette", true, PanelTone::Info);
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(3),
        ])
        .split(inner);

    let query = app
        .command_palette
        .as_ref()
        .map(|palette| palette.query.as_str())
        .unwrap_or("");
    frame.render_widget(
        Paragraph::new(vec![
            Line::from("Search actions and pages."),
            Line::from(format!("> {query}")),
        ]),
        sections[0],
    );

    let entries = app.palette_entries();
    let items: Vec<ListItem> = if entries.is_empty() {
        vec![ListItem::new("No commands matched the current query.")]
    } else {
        entries
            .iter()
            .map(|entry| {
                ListItem::new(vec![
                    Line::from(Span::styled(
                        entry.title.clone(),
                        Style::default().fg(COLOR_FG_MAIN),
                    )),
                    Line::from(Span::styled(
                        entry.detail.clone(),
                        Style::default().fg(COLOR_MUTED),
                    )),
                ])
            })
            .collect()
    };

    let mut state = ListState::default();
    if !entries.is_empty() {
        let selected = app
            .command_palette
            .as_ref()
            .map(|palette| min(palette.selected, entries.len() - 1))
            .unwrap_or(0);
        state.select(Some(selected));
    }

    let list = List::new(items).highlight_style(
        Style::default()
            .bg(COLOR_ACCENT_SOFT)
            .fg(COLOR_FG_MAIN)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_stateful_widget(list, sections[1], &mut state);

    frame.render_widget(
        Paragraph::new("Esc closes. Enter runs the selected action. Up/Down move the selection.")
            .wrap(Wrap { trim: true }),
        sections[2],
    );
}

fn render_help_modal(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(76, 68, area);
    frame.render_widget(Clear, popup);
    let inner = draw_panel(frame, popup, "Help", true, PanelTone::Info);
    let help = Paragraph::new(vec![
        Line::from("Global navigation"),
        Line::from("  Up/Down move through the visible main menu or submenu."),
        Line::from("  Enter opens the selected main menu submenu, or runs the selected submenu option."),
        Line::from("  Esc returns from options to the main menu."),
        Line::from("  Esc on the main menu opens a selectable Yes/No prompt to return to the login shell."),
        Line::from("  ? opens this help modal. : opens the command palette."),
        Line::from(""),
        Line::from("Page model"),
        Line::from("  The left rail shows either the primary menu or the selected submenu."),
        Line::from("  The right side is contextual and read-only until an option opens a modal or command."),
        Line::from("  SSH keys, update targets, and log controls stay in their section submenus."),
        Line::from("  Apply Configuration asks to commit uncommitted files before switching the host."),
        Line::from("  From a regular SSH shell, run maestro-menu manually to open this console."),
        Line::from(""),
        Line::from("Current page"),
        Line::from(format!("  {}", app.page_title())),
        Line::from(format!("  Selected option: {}", app.selected_sidebar_title())),
        Line::from(format!("  Focus: {}", focus_label(app.focus))),
        Line::from(""),
        Line::from("Esc closes this help modal."),
    ])
    .wrap(Wrap { trim: true });
    frame.render_widget(help, inner);
}

fn aligned_key_value_line(
    label: &str,
    value: &str,
    color: Color,
    label_width: usize,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:<label_width$}"),
            Style::default().fg(COLOR_MUTED_2),
        ),
        Span::raw("  "),
        Span::styled(value.to_string(), Style::default().fg(color)),
    ])
}

fn key_value_line(label: &str, value: &str, color: Color) -> Line<'static> {
    aligned_key_value_line(label, value, color, PANEL_LABEL_WIDTH)
}

fn header_key_value_line(label: &str, value: &str, color: Color) -> Line<'static> {
    aligned_key_value_line(label, value, color, HEADER_LABEL_WIDTH)
}

fn focus_label(focus: Focus) -> &'static str {
    match focus {
        Focus::PrimaryMenu => "Main Menu",
        Focus::Options => "Options",
    }
}

fn last_apply_label(snapshot: &Snapshot) -> String {
    if let Some(last_apply) = &snapshot.last_apply {
        format!(
            "{} {} on {} @ {}{} [{}]",
            last_apply.result,
            last_apply.action,
            last_apply.hostname,
            last_apply.timestamp,
            if last_apply.first_install {
                " (first install)"
            } else {
                ""
            },
            short_sha(&last_apply.head)
        )
    } else {
        "not recorded".to_string()
    }
}

fn sudo_command() -> Command {
    Command::new(sudo_program())
}

fn sudo_program() -> &'static str {
    if Path::new("/run/wrappers/bin/sudo").exists() {
        "/run/wrappers/bin/sudo"
    } else {
        "sudo"
    }
}

fn nh_command() -> Command {
    if Path::new("/run/current-system/sw/bin/nh").exists() {
        Command::new("/run/current-system/sw/bin/nh")
    } else {
        Command::new("nh")
    }
}

fn check_flake_updates(repo_root: &Path) -> UpdateStatus {
    let current_lock = repo_root.join("flake.lock");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let temp_lock = env::temp_dir().join(format!("maestro-menu-{nonce}.lock"));
    let timeout_seconds = UPDATE_TIMEOUT_SECS.to_string();
    let repo_arg = repo_root.to_string_lossy().to_string();
    let lock_arg = temp_lock.to_string_lossy().to_string();

    let output = Command::new("timeout")
        .args([
            timeout_seconds.as_str(),
            "nix",
            "flake",
            "update",
            "--flake",
            repo_arg.as_str(),
            "--output-lock-file",
            lock_arg.as_str(),
        ])
        .output();

    let status = match output {
        Ok(output) => {
            if output.status.success() {
                match count_lock_changes(&current_lock, &temp_lock) {
                    Ok(0) => UpdateStatus::UpToDate,
                    Ok(count) => UpdateStatus::Available(count),
                    Err(error) => UpdateStatus::Error(error.to_string()),
                }
            } else {
                let message = render_output(&output);
                UpdateStatus::Error(if message.is_empty() {
                    "nix flake update returned a non-zero status".to_string()
                } else {
                    message
                })
            }
        }
        Err(error) => UpdateStatus::Error(error.to_string()),
    };

    let _ = fs::remove_file(temp_lock);
    status
}

fn count_lock_changes(current_lock: &Path, updated_lock: &Path) -> Result<usize> {
    let current: FlakeLock = serde_json::from_slice(
        &fs::read(current_lock)
            .with_context(|| format!("failed to read {}", current_lock.display()))?,
    )
    .context("failed to parse current flake.lock")?;
    let updated: FlakeLock = serde_json::from_slice(
        &fs::read(updated_lock)
            .with_context(|| format!("failed to read {}", updated_lock.display()))?,
    )
    .context("failed to parse temporary flake.lock")?;

    let mut names = BTreeSet::new();
    names.extend(current.nodes.keys().cloned());
    names.extend(updated.nodes.keys().cloned());
    names.remove("root");

    Ok(names
        .into_iter()
        .filter(|name| {
            current.nodes.get(name).and_then(|node| node.locked.clone())
                != updated.nodes.get(name).and_then(|node| node.locked.clone())
        })
        .count())
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

fn truncate_middle(value: &str, max_width: usize) -> String {
    if value.chars().count() <= max_width {
        return value.to_string();
    }

    let keep = max_width.saturating_sub(3) / 2;
    let start: String = value.chars().take(keep).collect();
    let end: String = value
        .chars()
        .rev()
        .take(keep)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{start}...{end}")
}

fn truncate_end(value: &str, max_width: usize) -> String {
    if value.chars().count() <= max_width {
        return value.to_string();
    }

    if max_width <= 3 {
        return ".".repeat(max_width);
    }

    let visible: String = value.chars().take(max_width - 3).collect();
    format!("{visible}...")
}

fn open_shell() -> ! {
    let shell = env::var("SHELL").unwrap_or_else(|_| "/run/current-system/sw/bin/bash".to_string());
    let mut command = Command::new(shell);
    command.arg("-l").env("MAESTRO_TUI_BYPASS", "1");
    if let Some(path) = login_shell_path() {
        command.env("PATH", path);
    }

    let error = command.exec();
    panic!("failed to exec shell: {error}");
}

fn login_shell_path() -> Option<std::ffi::OsString> {
    let current_path = env::var_os("PATH")?;
    let cleaned_paths = env::split_paths(&current_path)
        .filter(|path| !is_direct_store_bin(path))
        .collect::<Vec<_>>();

    env::join_paths(cleaned_paths).ok()
}

fn is_direct_store_bin(path: &Path) -> bool {
    path.starts_with("/nix/store")
        && path
            .file_name()
            .map(|file_name| file_name == "bin")
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn sample_snapshot() -> Snapshot {
        Snapshot {
            hostname: "maestro-test".to_string(),
            username: "maestro".to_string(),
            timezone: "UTC".to_string(),
            extras: false,
            development_mode: false,
            ssh_keys: vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey maestro-test".to_string()],
            system_packages: vec!["vim".to_string(), "curl".to_string()],
            user_packages: vec!["git".to_string()],
            services: vec!["openssh".to_string()],
            dirty_count: 0,
            head: "0123456789abcdef".to_string(),
            branch: "main".to_string(),
            upstream: Some("origin/main".to_string()),
            ahead: 0,
            behind: 0,
            memory_total_bytes: 8 * 1024 * 1024 * 1024,
            memory_used_bytes: 3 * 1024 * 1024 * 1024,
            memory_used_percent: 38,
            storage_total_bytes: 64 * 1024 * 1024 * 1024,
            storage_used_bytes: 12 * 1024 * 1024 * 1024,
            storage_used_percent: 19,
            primary_ip: Some("192.0.2.10".to_string()),
            xen_orchestra_version: Some("test-version".to_string()),
            web_ui_url: Some("https://192.0.2.10".to_string()),
            rebuild_queued: false,
            rebuild_needed: false,
            last_apply: Some(ApplyState {
                result: "success".to_string(),
                action: "switch".to_string(),
                hostname: "maestro-test".to_string(),
                head: "0123456789abcdef".to_string(),
                first_install: false,
                exit_code: 0,
                timestamp: "2026-05-08T00:00:00Z".to_string(),
            }),
        }
    }

    fn render_text(app: &App) -> String {
        let backend = TestBackend::new(132, 38);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal.draw(|frame| render(frame, app)).expect("draw");
        terminal
            .backend_mut()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    #[test]
    fn header_uses_compact_title_without_ascii_art() {
        let app = App::new(PathBuf::from("/tmp/maestro-test"), sample_snapshot());
        let text = render_text(&app);

        assert!(text.contains("NiXO-CE"));
        assert!(!text.contains("_|      _|"));
        assert!(!text.contains("_|_|    _|"));
    }

    #[test]
    fn primary_left_menu_labels_render() {
        let app = App::new(PathBuf::from("/tmp/maestro-test"), sample_snapshot());
        let text = render_text(&app);

        for label in [
            "Status",
            "Host Setup",
            "Access",
            "Packages",
            "Updates",
            "Maintenance",
            "Logs",
            "Shell",
        ] {
            assert!(text.contains(label), "missing primary menu label {label}");
        }
    }

    #[test]
    fn main_menu_hides_submenu_options() {
        let app = App::new(PathBuf::from("/tmp/maestro-test"), sample_snapshot());
        let text = render_text(&app);

        assert!(text.contains("Main Menu"));
        assert!(!text.contains("Status Options"));
        assert!(!text.contains("Refresh Snapshot"));
    }

    #[test]
    fn submenu_hides_main_menu() {
        let mut app = App::new(PathBuf::from("/tmp/maestro-test"), sample_snapshot());
        app.set_focus(Focus::Options);
        let text = render_text(&app);

        assert!(text.contains("Status Options"));
        assert!(text.contains("Refresh Snapshot"));
        assert!(!text.contains("Main Menu"));
    }

    #[test]
    fn updates_section_keeps_targets_left_and_details_right() {
        let mut app = App::new(PathBuf::from("/tmp/maestro-test"), sample_snapshot());
        app.set_page(Page::Updates);
        app.set_focus(Focus::Options);
        let text = render_text(&app);

        assert!(text.contains("Update nixpkgs"));
        assert!(text.contains("Update Home Manager"));
        assert!(text.contains("Selected Target"));
        assert!(text.contains("Each update commits only flake.lock."));
    }

    #[test]
    fn quit_confirmation_renders_selectable_yes_no() {
        let mut app = App::new(PathBuf::from("/tmp/maestro-test"), sample_snapshot());
        app.open_quit_confirm();
        let text = render_text(&app);

        assert!(text.contains("Return to Shell?"));
        assert!(text.contains("Yes"));
        assert!(text.contains("No"));
        assert!(text.contains("Use arrows and Enter"));
    }

    #[test]
    fn generated_apply_commit_message_includes_date_and_files() {
        let message = autogenerated_commit_message(&[
            GitStatusEntry {
                status: " M".to_string(),
                path: "flake.lock".to_string(),
            },
            GitStatusEntry {
                status: "??".to_string(),
                path: "host/menu.nix".to_string(),
            },
        ]);

        assert!(message.contains("Save Maestro changes on "));
        assert!(message.contains("flake.lock"));
        assert!(message.contains("host/menu.nix"));
    }
}

use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver},
    Arc,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui::epaint::Shadow;
use eframe::egui::{
    self, pos2, vec2, Align, Color32, FontFamily, FontId, Layout, Rect, RichText, Rounding, Sense,
    Stroke, TextEdit, Vec2,
};
use rfd::FileDialog;
use serde::Serialize;

use crate::engine::{
    run_scan, ScanEvent, ScanPolicy, ScanRequest, ScanResult, ScanSummary, ScanTarget, Verdict,
};
use crate::feeds::{self, FeedSyncSummary};
use crate::signatures::{add_signature, HashAlgorithm};

const VERSION: &str = "0.3.0";

const BG: Color32 = Color32::from_rgb(10, 14, 22);
const BG_LAYER: Color32 = Color32::from_rgb(15, 22, 33);
const HERO: Color32 = Color32::from_rgb(18, 27, 40);
const SURFACE: Color32 = Color32::from_rgb(20, 30, 43);
const SURFACE_ALT: Color32 = Color32::from_rgb(24, 36, 50);
const STROKE: Color32 = Color32::from_rgb(42, 60, 81);
const TEXT: Color32 = Color32::from_rgb(236, 243, 247);
const MUTED: Color32 = Color32::from_rgb(141, 156, 172);
const ACCENT: Color32 = Color32::from_rgb(106, 208, 202);
const ACCENT_SOFT: Color32 = Color32::from_rgb(41, 74, 80);
const SUCCESS: Color32 = Color32::from_rgb(90, 209, 142);
const WARNING: Color32 = Color32::from_rgb(247, 187, 93);
const DANGER: Color32 = Color32::from_rgb(255, 116, 102);

#[derive(Clone, Copy, Eq, PartialEq)]
enum TargetMode {
    File,
    Directory,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResultFilter {
    All,
    Malicious,
    Errors,
    Clean,
}

#[derive(Default)]
struct ScanProgress {
    total: usize,
    completed: usize,
    signature_count: usize,
    rule_files: usize,
}

enum FeedSyncEvent {
    Completed(FeedSyncSummary),
    Failed(String),
}

#[derive(Clone, Copy)]
enum MetricIcon {
    Processed,
    HashDetections,
    YaraDetections,
    Elapsed,
}

pub struct AstraApp {
    target_mode: TargetMode,
    target_path: String,
    database_path: String,
    rules_path: String,
    enable_yara: bool,
    skip_hidden_paths: bool,
    max_file_size_mb: String,
    results: Vec<ScanResult>,
    selected_result: Option<usize>,
    result_filter: ResultFilter,
    results_search: String,
    summary: Option<ScanSummary>,
    progress: ScanProgress,
    scan_events: Option<Receiver<ScanEvent>>,
    feed_sync_events: Option<Receiver<FeedSyncEvent>>,
    cancel_flag: Option<Arc<AtomicBool>>,
    is_scanning: bool,
    is_syncing_feeds: bool,
    status_message: String,
    feed_status_message: String,
    feed_summary: Option<FeedSyncSummary>,
    add_hash_value: String,
    add_hash_type: HashAlgorithm,
    add_threat_name: String,
}

impl AstraApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_theme(&cc.egui_ctx);

        let database_path = default_data_path("signatures/hashes.txt")
            .unwrap_or_else(|| PathBuf::from("signatures/hashes.txt"));
        let rules_path = default_data_path("feeds/rules")
            .or_else(|| default_data_path("rules"))
            .unwrap_or_else(|| PathBuf::from("rules"));

        Self {
            target_mode: TargetMode::File,
            target_path: String::new(),
            database_path: database_path.display().to_string(),
            rules_path: rules_path.display().to_string(),
            enable_yara: rules_path.exists(),
            skip_hidden_paths: true,
            max_file_size_mb: String::new(),
            results: Vec::new(),
            selected_result: None,
            result_filter: ResultFilter::All,
            results_search: String::new(),
            summary: None,
            progress: ScanProgress::default(),
            scan_events: None,
            feed_sync_events: None,
            cancel_flag: None,
            is_scanning: false,
            is_syncing_feeds: false,
            status_message: "Workspace armed. Select a target to begin.".to_string(),
            feed_status_message: "Curated feeds not synced yet.".to_string(),
            feed_summary: None,
            add_hash_value: String::new(),
            add_hash_type: HashAlgorithm::Sha256,
            add_threat_name: String::new(),
        }
    }

    fn start_scan(&mut self) {
        let target_path = PathBuf::from(self.target_path.trim());
        let database_path = PathBuf::from(self.database_path.trim());

        let target = match self.target_mode {
            TargetMode::File => ScanTarget::File(target_path),
            TargetMode::Directory => ScanTarget::Directory(target_path),
        };

        let rules_path = if self.enable_yara {
            Some(PathBuf::from(self.rules_path.trim()))
        } else {
            None
        };
        let max_file_size_bytes = match parse_max_file_size_mb(&self.max_file_size_mb) {
            Ok(value) => value,
            Err(error) => {
                self.status_message = error;
                return;
            }
        };

        let request = ScanRequest {
            target,
            database_path,
            rules_path,
            policy: ScanPolicy {
                skip_hidden_paths: self.skip_hidden_paths,
                max_file_size_bytes,
            },
        };

        if let Err(error) = validate_request(&request) {
            self.status_message = error;
            return;
        }

        let (sender, receiver) = mpsc::channel();
        self.results.clear();
        self.selected_result = None;
        self.summary = None;
        self.progress = ScanProgress::default();
        self.scan_events = Some(receiver);
        let cancel_flag = Arc::new(AtomicBool::new(false));
        self.cancel_flag = Some(cancel_flag.clone());
        self.is_scanning = true;
        self.status_message =
            "Scan dispatched. Hashing and rule evaluation in progress.".to_string();

        thread::spawn(move || run_scan(request, sender, cancel_flag));
    }

    fn stop_scan(&mut self) {
        if let Some(cancel_flag) = &self.cancel_flag {
            cancel_flag.store(true, Ordering::Relaxed);
            self.status_message = "Stopping scan after the current file completes.".to_string();
        }
    }

    fn sync_curated_feeds(&mut self) {
        let (sender, receiver) = mpsc::channel();
        self.feed_sync_events = Some(receiver);
        self.is_syncing_feeds = true;
        self.feed_status_message = "Syncing curated threat feeds...".to_string();

        thread::spawn(move || {
            let result = feeds::sync_curated_feeds(&feeds::default_feed_rules_dir());
            let event = match result {
                Ok(summary) => FeedSyncEvent::Completed(summary),
                Err(error) => FeedSyncEvent::Failed(error.to_string()),
            };
            let _ = sender.send(event);
        });
    }

    fn poll_scan_events(&mut self) {
        let mut disconnect = false;

        if let Some(receiver) = &self.scan_events {
            while let Ok(event) = receiver.try_recv() {
                match event {
                    ScanEvent::Started {
                        total,
                        signature_count,
                        rule_files,
                    } => {
                        self.progress.total = total;
                        self.progress.signature_count = signature_count;
                        self.progress.rule_files = rule_files;
                        self.status_message = format!(
                            "Loaded {signature_count} signatures and {rule_files} YARA rule file(s)."
                        );
                    }
                    ScanEvent::FileScanned(result) => {
                        self.progress.completed += 1;
                        self.results.push(result);
                        if self.selected_result.is_none() {
                            self.selected_result = Some(0);
                        }
                    }
                    ScanEvent::Failed(message) => {
                        self.status_message = message;
                        self.is_scanning = false;
                        disconnect = true;
                    }
                    ScanEvent::Finished { summary, cancelled } => {
                        self.summary = Some(summary.clone());
                        self.status_message = if cancelled {
                            format!(
                                "Scan stopped: {} files inspected before cancellation.",
                                summary.files_scanned
                            )
                        } else {
                            format!(
                                "Scan complete: {} files inspected, {} hash hits, {} YARA hits.",
                                summary.files_scanned,
                                summary.hash_detections,
                                summary.yara_detections
                            )
                        };
                        self.is_scanning = false;
                        disconnect = true;
                    }
                }
            }
        }

        if disconnect {
            self.scan_events = None;
            self.cancel_flag = None;
        }

        let mut feed_disconnect = false;
        if let Some(receiver) = &self.feed_sync_events {
            while let Ok(event) = receiver.try_recv() {
                match event {
                    FeedSyncEvent::Completed(summary) => {
                        self.enable_yara = true;
                        self.rules_path = summary.destination.display().to_string();
                        self.feed_status_message = format!(
                            "Synced {} feeds and {} rules into {}.",
                            summary.synced_feeds,
                            summary.total_rules,
                            summary.destination.display()
                        );
                        self.feed_summary = Some(summary);
                        self.is_syncing_feeds = false;
                        feed_disconnect = true;
                    }
                    FeedSyncEvent::Failed(message) => {
                        self.feed_status_message = message;
                        self.is_syncing_feeds = false;
                        feed_disconnect = true;
                    }
                }
            }
        }
        if feed_disconnect {
            self.feed_sync_events = None;
        }
    }

    fn add_signature(&mut self) {
        let path = PathBuf::from(self.database_path.trim());
        match add_signature(
            &path,
            self.add_hash_type,
            &self.add_hash_value,
            &self.add_threat_name,
        ) {
            Ok(()) => {
                self.add_hash_value.clear();
                self.add_threat_name.clear();
                self.status_message = format!(
                    "Added {} signature to {}.",
                    self.add_hash_type,
                    path.display()
                );
            }
            Err(error) => {
                self.status_message = error.to_string();
            }
        }
    }

    fn export_report(&mut self) {
        let Some(summary) = &self.summary else {
            self.status_message = "Run a scan before exporting a report.".to_string();
            return;
        };

        let Some(path) = FileDialog::new()
            .set_file_name("astra-sentinel-report.json")
            .add_filter("JSON", &["json"])
            .save_file()
        else {
            return;
        };

        let report = ScanReport::from_app(self, summary.clone());
        match serde_json::to_string_pretty(&report) {
            Ok(json) => match std::fs::write(&path, json) {
                Ok(()) => {
                    self.status_message = format!("Exported report to {}.", path.display());
                }
                Err(error) => {
                    self.status_message = format!("Failed to write report: {error}");
                }
            },
            Err(error) => {
                self.status_message = format!("Failed to serialize report: {error}");
            }
        }
    }

    fn filtered_result_indices(&self) -> Vec<usize> {
        let query = self.results_search.trim().to_ascii_lowercase();

        self.results
            .iter()
            .enumerate()
            .filter(|(_, result)| matches_result_filter(result, self.result_filter))
            .filter(|(_, result)| {
                if query.is_empty() {
                    return true;
                }

                let path = result.file_path.display().to_string().to_ascii_lowercase();
                let threat = result
                    .threat_name
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                path.contains(&query) || threat.contains(&query)
            })
            .map(|(index, _)| index)
            .collect()
    }
}

#[derive(Serialize)]
struct ScanReport {
    product: String,
    version: String,
    generated_at_epoch_seconds: u64,
    target_mode: String,
    target_path: String,
    signature_database: String,
    yara_enabled: bool,
    yara_rules_path: Option<String>,
    skip_hidden_paths: bool,
    max_file_size_mb: Option<u64>,
    summary: SerializableSummary,
    results: Vec<SerializableResult>,
}

#[derive(Serialize)]
struct SerializableSummary {
    files_scanned: usize,
    hash_detections: usize,
    yara_detections: usize,
    errors: usize,
    skipped_files: usize,
    elapsed_ms: u128,
}

#[derive(Serialize)]
struct SerializableResult {
    file_path: String,
    verdict: String,
    detected: bool,
    threat_name: Option<String>,
    match_type: Option<String>,
    match_hash: Option<String>,
    hashes: SerializableHashes,
    yara_matches: Vec<SerializableYaraMatch>,
    error: Option<String>,
    scan_time_ms: u128,
}

#[derive(Serialize)]
struct SerializableHashes {
    md5: String,
    sha1: String,
    sha256: String,
}

#[derive(Serialize)]
struct SerializableYaraMatch {
    rule_name: String,
    namespace: String,
    tags: Vec<String>,
    strings: Vec<SerializableYaraString>,
}

#[derive(Serialize)]
struct SerializableYaraString {
    name: String,
    offset: u64,
    preview: String,
}

impl ScanReport {
    fn from_app(app: &AstraApp, summary: ScanSummary) -> Self {
        Self {
            product: "Astra Sentinel".to_string(),
            version: VERSION.to_string(),
            generated_at_epoch_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_secs())
                .unwrap_or_default(),
            target_mode: mode_label(app.target_mode).to_string(),
            target_path: app.target_path.clone(),
            signature_database: app.database_path.clone(),
            yara_enabled: app.enable_yara,
            yara_rules_path: app.enable_yara.then(|| app.rules_path.clone()),
            skip_hidden_paths: app.skip_hidden_paths,
            max_file_size_mb: parse_max_file_size_mb(&app.max_file_size_mb)
                .ok()
                .flatten()
                .map(|bytes| bytes / (1024 * 1024)),
            summary: SerializableSummary {
                files_scanned: summary.files_scanned,
                hash_detections: summary.hash_detections,
                yara_detections: summary.yara_detections,
                errors: summary.errors,
                skipped_files: summary.skipped_files,
                elapsed_ms: summary.elapsed.as_millis(),
            },
            results: app.results.iter().map(SerializableResult::from).collect(),
        }
    }
}

impl From<&ScanResult> for SerializableResult {
    fn from(result: &ScanResult) -> Self {
        Self {
            file_path: result.file_path.display().to_string(),
            verdict: result.verdict.label().to_string(),
            detected: result.detected,
            threat_name: result.threat_name.clone(),
            match_type: result.match_type.map(|value| value.to_string()),
            match_hash: result.match_hash.clone(),
            hashes: SerializableHashes {
                md5: result.md5.clone(),
                sha1: result.sha1.clone(),
                sha256: result.sha256.clone(),
            },
            yara_matches: result
                .yara_matches
                .iter()
                .map(|matched_rule| SerializableYaraMatch {
                    rule_name: matched_rule.rule_name.clone(),
                    namespace: matched_rule.namespace.clone(),
                    tags: matched_rule.tags.clone(),
                    strings: matched_rule
                        .strings
                        .iter()
                        .map(|matched_string| SerializableYaraString {
                            name: matched_string.name.clone(),
                            offset: matched_string.offset,
                            preview: preview_bytes(&matched_string.data),
                        })
                        .collect(),
                })
                .collect(),
            error: result.error.clone(),
            scan_time_ms: result.scan_time.as_millis(),
        }
    }
}

impl eframe::App for AstraApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_scan_events();
        if self.is_scanning {
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(20.0)),
            )
            .show(ctx, |ui| {
                paint_background(ui);
                render_hero(ui, self);
                ui.add_space(18.0);

                let body_height = ui.available_height().max(480.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(ui.available_width(), body_height),
                    Layout::left_to_right(Align::Min),
                    |ui| {
                        ui.allocate_ui_with_layout(
                            Vec2::new(360.0, body_height),
                            Layout::top_down(Align::Min),
                            |ui| render_sidebar(ui, self),
                        );

                        ui.add_space(18.0);

                        ui.allocate_ui_with_layout(
                            Vec2::new(ui.available_width(), body_height),
                            Layout::top_down(Align::Min),
                            |ui| render_dashboard(ui, self),
                        );
                    },
                );
            });
    }
}

fn configure_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.spacing.item_spacing = vec2(12.0, 12.0);
    style.spacing.button_padding = vec2(14.0, 10.0);
    style.spacing.menu_margin = egui::Margin::same(12.0);
    style.spacing.window_margin = egui::Margin::same(18.0);
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = SURFACE;
    style.visuals.extreme_bg_color = BG_LAYER;
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.window_rounding = Rounding::same(22.0);
    style.visuals.window_stroke = Stroke::new(1.0, STROKE);
    style.visuals.window_shadow = Shadow {
        offset: vec2(0.0, 20.0),
        blur: 48.0,
        spread: 0.0,
        color: Color32::from_black_alpha(110),
    };
    style.visuals.selection.bg_fill = ACCENT_SOFT;
    style.visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    style.visuals.widgets.noninteractive.bg_fill = SURFACE;
    style.visuals.widgets.noninteractive.weak_bg_fill = SURFACE;
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, STROKE);
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, MUTED);
    style.visuals.widgets.noninteractive.rounding = Rounding::same(18.0);
    style.visuals.widgets.inactive.bg_fill = SURFACE_ALT;
    style.visuals.widgets.inactive.weak_bg_fill = SURFACE_ALT;
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, STROKE);
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.inactive.rounding = Rounding::same(18.0);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(33, 47, 63);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(33, 47, 63);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.hovered.rounding = Rounding::same(18.0);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(43, 65, 79);
    style.visuals.widgets.active.weak_bg_fill = Color32::from_rgb(43, 65, 79);
    style.visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.active.rounding = Rounding::same(18.0);
    style.visuals.faint_bg_color = Color32::from_rgb(18, 27, 40);
    style.text_styles.insert(
        egui::TextStyle::Heading,
        FontId::new(28.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Body,
        FontId::new(15.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        FontId::new(15.0, FontFamily::Proportional),
    );
    ctx.set_style(style);
}

fn paint_background(ui: &egui::Ui) {
    let rect = ui.max_rect();
    let painter = ui.painter();
    painter.rect_filled(rect, 0.0, BG);
    painter.circle_filled(
        rect.left_top() + vec2(rect.width() * 0.12, 120.0),
        220.0,
        Color32::from_rgba_unmultiplied(26, 112, 116, 42),
    );
    painter.circle_filled(
        rect.right_top() + vec2(-180.0, 80.0),
        180.0,
        Color32::from_rgba_unmultiplied(53, 84, 173, 34),
    );
    painter.circle_filled(
        rect.left_bottom() + vec2(260.0, -120.0),
        150.0,
        Color32::from_rgba_unmultiplied(196, 102, 64, 18),
    );
}

fn render_hero(ui: &mut egui::Ui, app: &mut AstraApp) {
    egui::Frame::none()
        .fill(HERO)
        .stroke(Stroke::new(1.0, Color32::from_rgb(49, 68, 92)))
        .rounding(Rounding::same(28.0))
        .shadow(card_shadow(90))
        .inner_margin(egui::Margin::same(22.0))
        .show(ui, |ui| {
            ui.horizontal_top(|ui| {
                let action_width = 340.0;
                let narrative_width = (ui.available_width() - action_width - 18.0).max(460.0);

                ui.allocate_ui_with_layout(
                    Vec2::new(narrative_width, 0.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        label_caption(ui, "THREAT ANALYSIS WORKSTATION");
                        ui.label(
                            RichText::new("ASTRA SENTINEL")
                                .size(34.0)
                                .strong()
                                .color(TEXT),
                        );
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(
                                "Signature-based triage and YARA-backed inspection in a native Rust desktop console.",
                            )
                            .size(15.0)
                            .color(MUTED),
                        );
                        ui.add_space(18.0);
                        ui.horizontal_wrapped(|ui| {
                            badge(ui, mode_label(app.target_mode), ACCENT, ACCENT_SOFT);
                            badge(
                                ui,
                                if app.enable_yara { "YARA Enabled" } else { "YARA Disabled" },
                                if app.enable_yara { WARNING } else { MUTED },
                                Color32::from_rgb(49, 41, 25),
                            );
                            badge(ui, &format!("v{VERSION}"), TEXT, Color32::from_rgb(32, 44, 58));
                        });
                    },
                );

                ui.add_space(18.0);

                ui.allocate_ui_with_layout(
                    Vec2::new(action_width, 0.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        egui::Frame::none()
                            .fill(Color32::from_rgb(16, 24, 35))
                            .stroke(Stroke::new(1.0, STROKE))
                            .rounding(Rounding::same(22.0))
                            .inner_margin(egui::Margin::same(18.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let start = primary_button(
                                        ui,
                                        if app.is_scanning {
                                            "Scan Running"
                                        } else {
                                            "Start Scan"
                                        },
                                        !app.is_scanning,
                                    );
                                    if start.clicked() {
                                        app.start_scan();
                                    }

                                    let stop = secondary_button_enabled(
                                        ui,
                                        "Stop Scan",
                                        app.is_scanning,
                                        132.0,
                                        48.0,
                                    );
                                    if stop.clicked() {
                                        app.stop_scan();
                                    }
                                });

                                ui.add_space(16.0);
                                ui.label(
                                    RichText::new("Current Status")
                                        .size(12.0)
                                        .color(MUTED)
                                        .strong(),
                                );
                                ui.add_space(2.0);
                                ui.label(
                                    RichText::new(&app.status_message)
                                        .size(14.0)
                                        .color(TEXT),
                                );
                            });
                    },
                );
            });
        });
}

fn render_sidebar(ui: &mut egui::Ui, app: &mut AstraApp) {
    egui::ScrollArea::vertical()
        .id_salt("sidebar_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            card(
                ui,
                "Scan Control",
                "Configure targets and dispatch analysis.",
                |ui| {
                    let segmented_width = (ui.available_width() - 12.0) / 2.0;
                    ui.horizontal(|ui| {
                        mode_button(
                            ui,
                            &mut app.target_mode,
                            TargetMode::File,
                            "Single File",
                            segmented_width,
                        );
                        mode_button(
                            ui,
                            &mut app.target_mode,
                            TargetMode::Directory,
                            "Directory",
                            segmented_width,
                        );
                    });
                    ui.add_space(8.0);

                    path_picker_row(
                        ui,
                        "Target",
                        &mut app.target_path,
                        match app.target_mode {
                            TargetMode::File => "Choose file",
                            TargetMode::Directory => "Choose folder",
                        },
                        || match app.target_mode {
                            TargetMode::File => FileDialog::new()
                                .pick_file()
                                .map(|path| path.display().to_string()),
                            TargetMode::Directory => FileDialog::new()
                                .pick_folder()
                                .map(|path| path.display().to_string()),
                        },
                    );

                    path_picker_row(
                        ui,
                        "Signature Database",
                        &mut app.database_path,
                        "Browse",
                        || {
                            FileDialog::new()
                                .add_filter("Text", &["txt"])
                                .pick_file()
                                .map(|path| path.display().to_string())
                        },
                    );

                    toggle_row(ui, &mut app.enable_yara, "Enable YARA rule evaluation");
                    if app.enable_yara {
                        path_picker_row(ui, "YARA Rules", &mut app.rules_path, "Browse", || {
                            let selected = FileDialog::new()
                                .add_filter("YARA", &["yar", "yara"])
                                .pick_file()
                                .map(|path| path.display().to_string());
                            selected.or_else(|| {
                                FileDialog::new()
                                    .pick_folder()
                                    .map(|path| path.display().to_string())
                            })
                        });
                    }

                    ui.add_space(6.0);
                    field_label(ui, "Scan Policy");
                    toggle_row(
                        ui,
                        &mut app.skip_hidden_paths,
                        "Skip hidden files and folders",
                    );
                    input_row(
                        ui,
                        "Max File Size (MB)",
                        &mut app.max_file_size_mb,
                        "Blank = no size limit",
                    );

                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let scan = primary_button(ui, "Run Scan", !app.is_scanning);
                        if scan.clicked() {
                            app.start_scan();
                        }

                        let stop =
                            secondary_button_enabled(ui, "Stop Scan", app.is_scanning, 116.0, 40.0);
                        if stop.clicked() {
                            app.stop_scan();
                        }

                        let clear = secondary_button(ui, "Clear Results");
                        if clear.clicked() {
                            app.results.clear();
                            app.selected_result = None;
                            app.summary = None;
                            app.progress = ScanProgress::default();
                            app.status_message = "Results cleared. Workspace is ready.".to_string();
                        }
                    });
                },
            );

            ui.add_space(14.0);

            card(
                ui,
                "Threat Feeds",
                "Curated central repositories for expanding YARA coverage safely.",
                |ui| {
                    for feed in feeds::curated_feeds() {
                        info_strip(ui, feed.name, feed.description);
                        ui.label(RichText::new(feed.source_url).size(11.0).color(MUTED));
                    }

                    ui.add_space(8.0);
                    let sync = secondary_button_enabled(
                        ui,
                        "Sync Curated Feeds",
                        !app.is_syncing_feeds,
                        ui.available_width(),
                        40.0,
                    );
                    if sync.clicked() {
                        app.sync_curated_feeds();
                    }

                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(&app.feed_status_message)
                            .size(13.0)
                            .color(MUTED),
                    );

                    if let Some(summary) = &app.feed_summary {
                        ui.add_space(8.0);
                        info_strip(
                            ui,
                            "Active Feed Rules",
                            &format!(
                                "{} feeds | {} rules | {}",
                                summary.synced_feeds,
                                summary.total_rules,
                                truncate_middle(&summary.destination.display().to_string(), 34)
                            ),
                        );
                        for feed_status in &summary.per_feed {
                            info_strip(
                                ui,
                                feed_status.feed.name,
                                &format!("{} rules imported", feed_status.rule_count),
                            );
                        }
                    }
                },
            );

            ui.add_space(14.0);

            card(
                ui,
                "Signature Intelligence",
                "Append known-bad hashes to the local database without leaving the app.",
                |ui| {
                    field_label(ui, "Hash Type");
                    egui::ComboBox::from_id_salt("hash_type")
                        .selected_text(app.add_hash_type.to_string())
                        .width(ui.available_width())
                        .show_ui(ui, |ui| {
                            for variant in HashAlgorithm::variants() {
                                ui.selectable_value(
                                    &mut app.add_hash_type,
                                    variant,
                                    variant.to_string(),
                                );
                            }
                        });

                    input_row(
                        ui,
                        "Hash Value",
                        &mut app.add_hash_value,
                        "Paste MD5, SHA1, or SHA256",
                    );
                    input_row(
                        ui,
                        "Threat Name",
                        &mut app.add_threat_name,
                        "Example: Cobalt Strike Beacon",
                    );

                    let add = secondary_button(ui, "Add Signature");
                    if add.clicked() {
                        app.add_signature();
                    }
                },
            );

            ui.add_space(14.0);

            card(
                ui,
                "Operations",
                "Live scan health and workspace state.",
                |ui| {
                    status_line(ui, "Mode", mode_label(app.target_mode));
                    status_line(
                        ui,
                        "Progress",
                        &format!("{}/{}", app.progress.completed, app.progress.total.max(1)),
                    );
                    status_line(ui, "Signatures", &app.progress.signature_count.to_string());
                    status_line(ui, "Rule Files", &app.progress.rule_files.to_string());
                    status_line(
                        ui,
                        "Skipped",
                        &app.summary
                            .as_ref()
                            .map(|s| s.skipped_files)
                            .unwrap_or(0)
                            .to_string(),
                    );

                    ui.add_space(6.0);
                    let ratio = if app.progress.total > 0 {
                        app.progress.completed as f32 / app.progress.total as f32
                    } else {
                        0.0
                    };
                    ui.add(
                        egui::ProgressBar::new(ratio)
                            .desired_width(ui.available_width())
                            .fill(ACCENT)
                            .show_percentage(),
                    );

                    ui.add_space(8.0);
                    info_strip(ui, "Database", &truncate_middle(&app.database_path, 38));
                    if app.enable_yara {
                        info_strip(ui, "Rules", &truncate_middle(&app.rules_path, 38));
                    }
                    info_strip(
                        ui,
                        "Policy",
                        &format!(
                            "{} | {}",
                            if app.skip_hidden_paths {
                                "skip hidden"
                            } else {
                                "include hidden"
                            },
                            match parse_max_file_size_mb(&app.max_file_size_mb) {
                                Ok(Some(bytes)) => format!("max {} MB", bytes / (1024 * 1024)),
                                _ => "no size limit".to_string(),
                            }
                        ),
                    );

                    ui.add_space(8.0);
                    let export = secondary_button_enabled(
                        ui,
                        "Export Report",
                        app.summary.is_some(),
                        ui.available_width(),
                        40.0,
                    );
                    if export.clicked() {
                        app.export_report();
                    }
                },
            );
        });
}

fn render_dashboard(ui: &mut egui::Ui, app: &mut AstraApp) {
    render_summary_row(ui, app.summary.as_ref(), &app.progress);
    ui.add_space(16.0);
    let filtered_indices = app.filtered_result_indices();
    let total_width = ui.available_width();
    let panel_gap = 16.0;
    let mut left_width = (total_width * 0.42).clamp(340.0, 520.0);
    let min_detail_width = 420.0;
    if total_width - left_width - panel_gap < min_detail_width {
        left_width = (total_width - panel_gap - min_detail_width).max(300.0);
    }
    let detail_width = (total_width - left_width - panel_gap).max(320.0);

    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(
            Vec2::new(left_width, ui.available_height()),
            Layout::top_down(Align::Min),
            |ui| {
                render_results_panel(
                    ui,
                    &app.results,
                    &mut app.selected_result,
                    &mut app.result_filter,
                    &mut app.results_search,
                    &filtered_indices,
                )
            },
        );
        ui.add_space(16.0);
        ui.allocate_ui_with_layout(
            Vec2::new(detail_width, ui.available_height()),
            Layout::top_down(Align::Min),
            |ui| render_detail_panel(ui, &app.results, app.selected_result),
        );
    });
}

fn render_summary_row(ui: &mut egui::Ui, summary: Option<&ScanSummary>, progress: &ScanProgress) {
    let tile_gap = 12.0;

    egui::Frame::none()
        .fill(Color32::from_rgb(14, 21, 31))
        .stroke(Stroke::new(1.0, STROKE))
        .rounding(Rounding::same(24.0))
        .shadow(card_shadow(42))
        .inner_margin(egui::Margin::same(12.0))
        .show(ui, |ui| {
            let tile_width = ((ui.available_width() - tile_gap * 3.0) / 4.0).max(140.0);

            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = tile_gap;

                ui.allocate_ui_with_layout(
                    vec2(tile_width, 80.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        metric_card(
                            ui,
                            MetricIcon::Processed,
                            "Processed",
                            summary
                                .map(|value| value.files_scanned.to_string())
                                .unwrap_or_else(|| progress.completed.to_string()),
                            TEXT,
                        );
                    },
                );
                ui.allocate_ui_with_layout(
                    vec2(tile_width, 80.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        metric_card(
                            ui,
                            MetricIcon::HashDetections,
                            "Hash Detections",
                            summary
                                .map(|value| value.hash_detections.to_string())
                                .unwrap_or_else(|| "0".to_string()),
                            DANGER,
                        );
                    },
                );
                ui.allocate_ui_with_layout(
                    vec2(tile_width, 80.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        metric_card(
                            ui,
                            MetricIcon::YaraDetections,
                            "YARA Detections",
                            summary
                                .map(|value| value.yara_detections.to_string())
                                .unwrap_or_else(|| "0".to_string()),
                            WARNING,
                        );
                    },
                );
                ui.allocate_ui_with_layout(
                    vec2(tile_width, 80.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        metric_card(
                            ui,
                            MetricIcon::Elapsed,
                            "Elapsed",
                            summary
                                .map(|value| format_duration(value.elapsed))
                                .unwrap_or_else(|| "--".to_string()),
                            ACCENT,
                        );
                    },
                );
            });
        });
}

fn render_results_panel(
    ui: &mut egui::Ui,
    results: &[ScanResult],
    selected_result: &mut Option<usize>,
    filter: &mut ResultFilter,
    search: &mut String,
    filtered_indices: &[usize],
) {
    card(ui, "Scan Results", "Inspected files and verdicts.", |ui| {
        form_row(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 12.0;
                let count_width = 110.0;
                let field_width = (ui.available_width() - count_width - 12.0).max(120.0);
                ui.add_sized(
                    [field_width, 46.0],
                    field_text_edit(search, "Search by path or threat name"),
                );
                ui.allocate_ui_with_layout(
                    Vec2::new(count_width, 46.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        ui.label(
                            RichText::new(format!("{} shown", filtered_indices.len()))
                                .size(14.0)
                                .color(MUTED),
                        );
                    },
                );
            });
        });

        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            filter_chip(ui, filter, ResultFilter::All, "All");
            filter_chip(ui, filter, ResultFilter::Malicious, "Malicious");
            filter_chip(ui, filter, ResultFilter::Errors, "Errors");
            filter_chip(ui, filter, ResultFilter::Clean, "Clean");
        });
        ui.add_space(10.0);
        let scroll_height = ui.available_height().max(320.0);
        if results.is_empty() {
            empty_state(
                ui,
                "No results yet",
                "Start a scan to populate this queue with file verdicts and YARA matches.",
            );
            return;
        }
        if filtered_indices.is_empty() {
            empty_state(
                ui,
                "No matching results",
                "Adjust the search query or filter to see more files.",
            );
            return;
        }

        egui::ScrollArea::vertical()
            .id_salt("results_scroll")
            .max_height(scroll_height)
            .auto_shrink([false, false])
            .show_rows(ui, 112.0, filtered_indices.len(), |ui, row_range| {
                for row in row_range {
                    let index = filtered_indices[row];
                    let result = &results[index];
                    let selected = selected_result.map(|value| value == index).unwrap_or(false);
                    result_row(ui, result, selected, index, selected_result);
                    ui.add_space(10.0);
                }
            });
    });
}

fn render_detail_panel(ui: &mut egui::Ui, results: &[ScanResult], selected_result: Option<usize>) {
    card(
        ui,
        "Inspection Detail",
        "Hashes, verdicts, and rule-level evidence for the selected item.",
        |ui| {
            let scroll_height = ui.available_height().max(320.0);

            let Some(index) = selected_result else {
                empty_state(
                    ui,
                    "Nothing selected",
                    "Choose a result from the queue to inspect hashes, matched rules, and verdict context.",
                );
                return;
            };

            let Some(result) = results.get(index) else {
                empty_state(
                    ui,
                    "Selection lost",
                    "The selected result is no longer available.",
                );
                return;
            };

            egui::ScrollArea::vertical()
                .id_salt("detail_scroll")
                .max_height(scroll_height)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(truncate_middle(&result.file_path.display().to_string(), 96))
                            .size(20.0)
                            .strong()
                            .color(TEXT),
                    );
                    ui.add_space(12.0);

                    ui.horizontal_wrapped(|ui| {
                        verdict_badge(ui, &result.verdict);
                        if let Some(threat_name) = &result.threat_name {
                            badge(ui, threat_name, DANGER, Color32::from_rgb(68, 34, 33));
                        }
                        if let Some(match_type) = result.match_type {
                            badge(
                                ui,
                                &format!("Matched {}", match_type),
                                WARNING,
                                Color32::from_rgb(70, 53, 25),
                            );
                        }
                        badge(
                            ui,
                            &format!("Scan time {}", format_duration(result.scan_time)),
                            TEXT,
                            Color32::from_rgb(32, 44, 58),
                        );
                    });

                    if let Some(error) = &result.error {
                        ui.add_space(14.0);
                        info_panel(ui, "Scan Error", error, DANGER);
                    }

                    ui.add_space(14.0);
                    detail_section(ui, "Hashes", |ui| {
                        hash_row(ui, "MD5", &result.md5);
                        hash_row(ui, "SHA1", &result.sha1);
                        hash_row(ui, "SHA256", &result.sha256);
                        if let Some(match_hash) = &result.match_hash {
                            hash_row(ui, "Matched Hash", match_hash);
                        }
                    });

                    ui.add_space(14.0);
                    detail_section(ui, "Assessment", |ui| {
                        status_line(ui, "Verdict", result.verdict.label());
                        if let Some(threat_name) = &result.threat_name {
                            status_line(ui, "Threat", threat_name);
                        }
                        status_line(ui, "YARA Matches", &result.yara_matches.len().to_string());
                    });

                    ui.add_space(14.0);
                    detail_section(ui, "YARA Evidence", |ui| {
                        if result.yara_matches.is_empty() {
                            info_strip(ui, "Rules", "No YARA matches for this file.");
                            return;
                        }

                        for matched_rule in &result.yara_matches {
                            evidence_card(ui, matched_rule);
                            ui.add_space(10.0);
                        }
                    });
                });
        },
    );
}

fn render_summary_row_spacer(ui: &mut egui::Ui) {
    ui.add_space(0.0);
}

fn metric_card(ui: &mut egui::Ui, icon: MetricIcon, label: &str, value: String, accent: Color32) {
    egui::Frame::none()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, STROKE))
        .rounding(Rounding::same(22.0))
        .shadow(card_shadow(55))
        .inner_margin(egui::Margin::symmetric(14.0, 12.0))
        .show(ui, |ui| {
            ui.set_min_size(vec2(ui.available_width(), 76.0));
            ui.allocate_ui_with_layout(
                vec2(ui.available_width(), 52.0),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;

                    let value_width = if matches!(icon, MetricIcon::Elapsed) {
                        72.0
                    } else {
                        48.0
                    };
                    let label_width = (ui.available_width() - value_width).max(72.0);

                    ui.allocate_ui_with_layout(
                        vec2(label_width, 52.0),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            draw_metric_icon(ui, icon, accent);
                            ui.label(RichText::new(label).size(11.5).color(MUTED));
                        },
                    );

                    ui.allocate_ui_with_layout(
                        vec2(value_width, 52.0),
                        Layout::right_to_left(Align::Center),
                        |ui| {
                            ui.label(RichText::new(value).size(22.0).strong().color(TEXT));
                        },
                    );
                },
            );
        });
}

fn draw_metric_icon(ui: &mut egui::Ui, icon: MetricIcon, accent: Color32) {
    let (icon_rect, _) = ui.allocate_exact_size(vec2(24.0, 24.0), Sense::hover());
    let painter = ui.painter_at(icon_rect);
    painter.rect_filled(icon_rect, 9.0, accent.linear_multiply(0.14));

    let glyph_rect = icon_rect.shrink2(vec2(5.5, 5.5));
    let stroke = Stroke::new(1.7, accent);

    match icon {
        MetricIcon::Processed => draw_processed_icon(&painter, glyph_rect, stroke),
        MetricIcon::HashDetections => draw_hash_icon(&painter, glyph_rect, stroke),
        MetricIcon::YaraDetections => draw_yara_icon(&painter, glyph_rect, stroke),
        MetricIcon::Elapsed => draw_elapsed_icon(&painter, glyph_rect, stroke),
    }
}

fn draw_processed_icon(painter: &egui::Painter, rect: Rect, stroke: Stroke) {
    let left = rect.left();
    let right = rect.right();
    let top = rect.top();
    let bottom = rect.bottom();
    let fold = rect.width() * 0.26;

    let points = vec![
        pos2(left, top),
        pos2(right - fold, top),
        pos2(right, top + fold),
        pos2(right, bottom),
        pos2(left, bottom),
        pos2(left, top),
    ];

    for segment in points.windows(2) {
        painter.line_segment([segment[0], segment[1]], stroke);
    }

    painter.line_segment(
        [pos2(right - fold, top), pos2(right - fold, top + fold)],
        stroke,
    );
    painter.line_segment(
        [pos2(right - fold, top + fold), pos2(right, top + fold)],
        stroke,
    );
}

fn draw_hash_icon(painter: &egui::Painter, rect: Rect, stroke: Stroke) {
    let left_x = rect.left() + rect.width() * 0.32;
    let right_x = rect.left() + rect.width() * 0.62;
    let top_y = rect.top() + rect.height() * 0.18;
    let bottom_y = rect.bottom() - rect.height() * 0.18;

    painter.line_segment([pos2(left_x, top_y), pos2(left_x - 1.5, bottom_y)], stroke);
    painter.line_segment(
        [pos2(right_x, top_y), pos2(right_x - 1.5, bottom_y)],
        stroke,
    );

    let upper_y = rect.top() + rect.height() * 0.40;
    let lower_y = rect.top() + rect.height() * 0.67;
    let left = rect.left() + rect.width() * 0.14;
    let right = rect.right() - rect.width() * 0.12;

    painter.line_segment([pos2(left, upper_y), pos2(right, upper_y - 1.0)], stroke);
    painter.line_segment([pos2(left, lower_y), pos2(right, lower_y - 1.0)], stroke);
}

fn draw_yara_icon(painter: &egui::Painter, rect: Rect, stroke: Stroke) {
    let center = rect.center();
    let outer_radius = rect.width().min(rect.height()) * 0.42;
    let inner_radius = outer_radius * 0.45;

    painter.circle_stroke(center, outer_radius, stroke);
    painter.circle_stroke(center, inner_radius, stroke);
    painter.line_segment(
        [pos2(rect.left(), center.y), pos2(rect.right(), center.y)],
        stroke,
    );
    painter.line_segment(
        [pos2(center.x, rect.top()), pos2(center.x, rect.bottom())],
        stroke,
    );
}

fn draw_elapsed_icon(painter: &egui::Painter, rect: Rect, stroke: Stroke) {
    let center = rect.center();
    let radius = rect.width().min(rect.height()) * 0.42;

    painter.circle_stroke(center, radius, stroke);
    painter.line_segment(
        [center, pos2(center.x, rect.top() + rect.height() * 0.25)],
        stroke,
    );
    painter.line_segment(
        [
            center,
            pos2(
                rect.left() + rect.width() * 0.68,
                center.y + rect.height() * 0.10,
            ),
        ],
        stroke,
    );
    painter.circle_filled(center, 1.8, stroke.color);
}

fn card(ui: &mut egui::Ui, title: &str, subtitle: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, STROKE))
        .rounding(Rounding::same(24.0))
        .shadow(card_shadow(60))
        .inner_margin(egui::Margin::same(18.0))
        .show(ui, |ui| {
            ui.label(RichText::new(title).size(22.0).strong().color(TEXT));
            ui.label(RichText::new(subtitle).size(13.0).color(MUTED));
            ui.add_space(14.0);
            render_summary_row_spacer(ui);
            add_contents(ui);
        });
}

fn result_row(
    ui: &mut egui::Ui,
    result: &ScanResult,
    selected: bool,
    index: usize,
    selected_result: &mut Option<usize>,
) {
    let fill = if selected {
        Color32::from_rgb(31, 47, 62)
    } else {
        SURFACE_ALT
    };
    let accent = match result.verdict {
        Verdict::Clean => SUCCESS,
        Verdict::Malicious => DANGER,
        Verdict::Error => WARNING,
    };
    let display_name = result
        .file_path
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::to_owned)
        .unwrap_or_else(|| result.file_path.display().to_string());
    let label = format!(
        "{}\n{}\n{}",
        display_name,
        truncate_middle(&result.file_path.display().to_string(), 68),
        result.verdict.label()
    );
    let button = egui::Button::new(
        RichText::new(label)
            .size(14.0)
            .strong()
            .color(TEXT)
            .line_height(Some(20.0)),
    )
    .fill(fill)
    .stroke(Stroke::new(
        if selected { 1.5 } else { 1.0 },
        if selected { accent } else { STROKE },
    ))
    .rounding(Rounding::same(20.0))
    .min_size(Vec2::new(ui.available_width(), 92.0));

    if ui.add(button).clicked() {
        *selected_result = Some(index);
    }

    ui.add_space(-82.0);
    ui.horizontal(|ui| {
        ui.add_space(16.0);
        verdict_badge(ui, &result.verdict);
        if !result.yara_matches.is_empty() {
            badge(
                ui,
                &format!("{} YARA", result.yara_matches.len()),
                WARNING,
                Color32::from_rgb(69, 53, 25),
            );
        }
        if result.detected {
            badge(ui, "Hash Hit", DANGER, Color32::from_rgb(69, 34, 33));
        }
    });
    ui.add_space(58.0);
}

fn evidence_card(ui: &mut egui::Ui, matched_rule: &crate::yara::YaraMatch) {
    egui::Frame::none()
        .fill(Color32::from_rgb(18, 27, 38))
        .stroke(Stroke::new(1.0, STROKE))
        .rounding(Rounding::same(18.0))
        .inner_margin(egui::Margin::same(14.0))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{}::{}",
                        matched_rule.namespace, matched_rule.rule_name
                    ))
                    .strong()
                    .color(WARNING),
                );
                for tag in &matched_rule.tags {
                    badge(ui, tag, TEXT, Color32::from_rgb(44, 48, 63));
                }
            });
            ui.add_space(8.0);

            if matched_rule.strings.is_empty() {
                ui.label(RichText::new("Rule matched without string offsets.").color(MUTED));
                return;
            }

            for matched_string in &matched_rule.strings {
                let preview = preview_bytes(&matched_string.data);
                info_strip(
                    ui,
                    &format!("{} @ 0x{:x}", matched_string.name, matched_string.offset),
                    &preview,
                );
            }
        });
}

fn detail_section(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(Color32::from_rgb(18, 26, 38))
        .stroke(Stroke::new(1.0, STROKE))
        .rounding(Rounding::same(20.0))
        .inner_margin(egui::Margin::same(14.0))
        .show(ui, |ui| {
            ui.label(RichText::new(title).size(16.0).strong().color(TEXT));
            ui.add_space(10.0);
            add_contents(ui);
        });
}

fn empty_state(ui: &mut egui::Ui, title: &str, message: &str) {
    egui::Frame::none()
        .fill(Color32::from_rgb(17, 25, 36))
        .stroke(Stroke::new(1.0, STROKE))
        .rounding(Rounding::same(20.0))
        .inner_margin(egui::Margin::same(18.0))
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(36.0);
                ui.label(RichText::new(title).size(20.0).strong().color(TEXT));
                ui.add_space(6.0);
                ui.label(RichText::new(message).size(14.0).color(MUTED));
                ui.add_space(36.0);
            });
        });
}

fn info_panel(ui: &mut egui::Ui, title: &str, message: &str, accent: Color32) {
    egui::Frame::none()
        .fill(Color32::from_rgb(30, 20, 24))
        .stroke(Stroke::new(1.0, accent))
        .rounding(Rounding::same(18.0))
        .inner_margin(egui::Margin::same(14.0))
        .show(ui, |ui| {
            ui.label(RichText::new(title).strong().color(accent));
            ui.add_space(4.0);
            ui.label(RichText::new(message).color(TEXT));
        });
}

fn info_strip(ui: &mut egui::Ui, label: &str, value: &str) {
    egui::Frame::none()
        .fill(Color32::from_rgb(23, 33, 46))
        .rounding(Rounding::same(14.0))
        .inner_margin(egui::Margin::symmetric(12.0, 10.0))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(label).size(12.0).strong().color(MUTED));
                ui.label(RichText::new(value).size(13.0).color(TEXT));
            });
        });
}

fn status_line(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).size(13.0).color(MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(value).size(14.0).strong().color(TEXT));
        });
    });
}

fn hash_row(ui: &mut egui::Ui, label: &str, value: &str) {
    let display_value = if value.is_empty() {
        "-".to_string()
    } else {
        truncate_middle(value, 72)
    };
    info_strip(ui, label, &display_value);
}

fn badge(ui: &mut egui::Ui, label: &str, text_color: Color32, fill: Color32) {
    egui::Frame::none()
        .fill(fill)
        .rounding(Rounding::same(999.0))
        .inner_margin(egui::Margin::symmetric(10.0, 6.0))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(12.0).strong().color(text_color));
        });
}

fn verdict_badge(ui: &mut egui::Ui, verdict: &Verdict) {
    let (label, text, fill) = match verdict {
        Verdict::Clean => ("Clean", SUCCESS, Color32::from_rgb(21, 50, 40)),
        Verdict::Malicious => ("Malicious", DANGER, Color32::from_rgb(61, 28, 27)),
        Verdict::Error => ("Error", WARNING, Color32::from_rgb(62, 44, 22)),
    };
    badge(ui, label, text, fill);
}

fn filter_chip(ui: &mut egui::Ui, current: &mut ResultFilter, value: ResultFilter, label: &str) {
    let selected = *current == value;
    let button = egui::Button::new(RichText::new(label).size(13.0).strong().color(if selected {
        BG
    } else {
        TEXT
    }))
    .fill(if selected {
        ACCENT
    } else {
        Color32::from_rgb(23, 33, 46)
    })
    .stroke(Stroke::new(1.0, if selected { ACCENT } else { STROKE }))
    .rounding(Rounding::same(999.0))
    .min_size(Vec2::new(88.0, 32.0));

    if ui.add(button).clicked() {
        *current = value;
    }
}

fn mode_button(
    ui: &mut egui::Ui,
    current: &mut TargetMode,
    mode: TargetMode,
    label: &str,
    width: f32,
) {
    let selected = *current == mode;
    let button = egui::Button::new(RichText::new(label).size(14.0).strong().color(if selected {
        BG
    } else {
        TEXT
    }))
    .fill(if selected { ACCENT } else { SURFACE_ALT })
    .stroke(Stroke::new(1.0, if selected { ACCENT } else { STROKE }))
    .rounding(Rounding::same(16.0))
    .min_size(Vec2::new(width, 40.0));

    if ui.add(button).clicked() {
        *current = mode;
    }
}

fn toggle_row(ui: &mut egui::Ui, value: &mut bool, label: &str) {
    egui::Frame::none()
        .fill(Color32::from_rgb(18, 27, 38))
        .stroke(Stroke::new(1.0, STROKE))
        .rounding(Rounding::same(16.0))
        .inner_margin(egui::Margin::symmetric(12.0, 10.0))
        .show(ui, |ui| {
            ui.checkbox(value, RichText::new(label).size(14.0).color(TEXT));
        });
}

fn path_picker_row(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    button_label: &str,
    picker: impl FnOnce() -> Option<String>,
) {
    field_label(ui, label);
    form_row(ui, |ui| {
        let button_width = 148.0;
        let spacing = 10.0;
        let field_width = (ui.available_width() - button_width - spacing).max(120.0);

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = spacing;
            ui.add_sized([field_width, 46.0], field_text_edit(value, "Select a path"));
            let browse = path_action_button(ui, button_label);
            if browse.clicked() {
                if let Some(selected) = picker() {
                    *value = selected;
                }
            }
        });
    });
}

fn input_row(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    field_label(ui, label);
    form_row(ui, |ui| {
        ui.add_sized([ui.available_width(), 46.0], field_text_edit(value, hint));
    });
}

fn field_label(ui: &mut egui::Ui, label: &str) {
    ui.label(RichText::new(label).size(12.0).strong().color(MUTED));
}

fn label_caption(ui: &mut egui::Ui, label: &str) {
    ui.label(
        RichText::new(label)
            .size(12.0)
            .strong()
            .extra_letter_spacing(0.8)
            .color(ACCENT),
    );
}

fn field_text_edit<'a>(value: &'a mut String, hint: &'a str) -> TextEdit<'a> {
    TextEdit::singleline(value)
        .hint_text(hint)
        .font(FontId::new(14.0, FontFamily::Proportional))
        .vertical_align(Align::Center)
        .margin(egui::Margin::symmetric(14.0, 13.0))
        .clip_text(true)
        .desired_width(f32::INFINITY)
}

fn form_row(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(Color32::from_rgb(17, 26, 38))
        .stroke(Stroke::new(1.0, Color32::from_rgb(40, 58, 79)))
        .rounding(Rounding::same(18.0))
        .inner_margin(egui::Margin::same(10.0))
        .show(ui, |ui| {
            add_contents(ui);
        });
}

fn primary_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(label).size(15.0).strong().color(BG))
            .fill(ACCENT)
            .stroke(Stroke::new(1.0, ACCENT))
            .rounding(Rounding::same(18.0))
            .min_size(Vec2::new(ui.available_width().min(180.0), 48.0)),
    )
}

fn secondary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    secondary_button_enabled(ui, label, true, 96.0, 40.0)
}

fn secondary_button_enabled(
    ui: &mut egui::Ui,
    label: &str,
    enabled: bool,
    width: f32,
    height: f32,
) -> egui::Response {
    let response = ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(label).size(14.0).strong().color(TEXT))
            .fill(Color32::from_rgb(23, 33, 46))
            .stroke(Stroke::new(1.0, STROKE))
            .rounding(Rounding::same(16.0))
            .min_size(Vec2::new(width, height)),
    );

    if enabled {
        response
    } else {
        response.on_disabled_hover_text("No active scan")
    }
}

fn path_action_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label).size(14.0).strong().color(TEXT))
            .fill(Color32::from_rgb(23, 33, 46))
            .stroke(Stroke::new(1.0, STROKE))
            .rounding(Rounding::same(16.0))
            .min_size(Vec2::new(148.0, 46.0)),
    )
}

fn card_shadow(alpha: u8) -> Shadow {
    Shadow {
        offset: vec2(0.0, 16.0),
        blur: 36.0,
        spread: 0.0,
        color: Color32::from_black_alpha(alpha),
    }
}

fn validate_request(request: &ScanRequest) -> Result<(), String> {
    match &request.target {
        ScanTarget::File(path) if path.as_os_str().is_empty() => {
            Err("Select a file to scan.".to_string())
        }
        ScanTarget::Directory(path) if path.as_os_str().is_empty() => {
            Err("Select a directory to scan.".to_string())
        }
        _ if request.database_path.as_os_str().is_empty() => {
            Err("Select a signature database.".to_string())
        }
        _ if request
            .rules_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty()) =>
        {
            Err("Select a YARA rule file or directory.".to_string())
        }
        _ => Ok(()),
    }
}

fn parse_max_file_size_mb(value: &str) -> Result<Option<u64>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let mb = trimmed
        .parse::<u64>()
        .map_err(|_| "Max File Size (MB) must be a whole number.".to_string())?;
    if mb == 0 {
        return Err("Max File Size (MB) must be greater than zero.".to_string());
    }

    Ok(Some(mb * 1024 * 1024))
}

fn matches_result_filter(result: &ScanResult, filter: ResultFilter) -> bool {
    match filter {
        ResultFilter::All => true,
        ResultFilter::Malicious => matches!(result.verdict, Verdict::Malicious),
        ResultFilter::Errors => matches!(result.verdict, Verdict::Error),
        ResultFilter::Clean => matches!(result.verdict, Verdict::Clean),
    }
}

fn preview_bytes(bytes: &[u8]) -> String {
    let preview = if bytes.len() > 40 {
        &bytes[..40]
    } else {
        bytes
    };
    let mut text = String::from_utf8_lossy(preview).into_owned();
    if bytes.len() > 40 {
        text.push_str("...");
    }
    text
}

fn truncate_middle(value: &str, max_chars: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= max_chars {
        return value.to_string();
    }

    let head = max_chars / 2 - 2;
    let tail = max_chars.saturating_sub(head + 3);
    format!(
        "{}...{}",
        chars[..head].iter().collect::<String>(),
        chars[chars.len() - tail..].iter().collect::<String>()
    )
}

fn mode_label(mode: TargetMode) -> &'static str {
    match mode {
        TargetMode::File => "Single File",
        TargetMode::Directory => "Directory Sweep",
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs_f64() >= 1.0 {
        format!("{:.2}s", duration.as_secs_f64())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

fn default_data_path(relative: &str) -> Option<PathBuf> {
    let relative_path = Path::new(relative);
    let current_dir = std::env::current_dir().ok()?;
    let executable_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf));

    for candidate_root in [Some(current_dir), executable_dir].into_iter().flatten() {
        let candidate = candidate_root.join(relative_path);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

mod app;
mod engine;
mod feeds;
mod signatures;
mod yara;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 860.0])
            .with_min_inner_size([1120.0, 720.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Astra Sentinel",
        options,
        Box::new(|cc| Ok(Box::new(app::AstraApp::new(cc)))),
    )
}

//! Sentinel Report - Multi-Format Report Exporter (HTML, JSON, Terminal)

pub mod html;
pub mod json;
pub mod terminal;

pub use html::{generate_html_report, render_html_string};
pub use json::export_json_report;
pub use terminal::print_terminal_summary;

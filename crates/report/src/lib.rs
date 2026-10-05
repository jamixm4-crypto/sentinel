//! Sentinel Report - Multi-Format Report Exporter (HTML, JSON, Terminal)

pub mod html;
pub mod json;
pub mod terminal;

pub use html::{generate_html_report, render_html_string};
pub use json::{export_ecs_ndjson, export_ecs_report, export_json_report, generate_ecs_events};
pub use terminal::print_terminal_summary;

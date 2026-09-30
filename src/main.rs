macro_rules! print {
    ($($arg:tt)*) => {{
        crate::terminal_output::write_stdout(format_args!($($arg)*), false)
    }};
}

macro_rules! println {
    () => {{ crate::terminal_output::write_stdout(format_args!(""), true) }};
    ($($arg:tt)*) => {{
        crate::terminal_output::write_stdout(format_args!($($arg)*), true)
    }};
}

macro_rules! eprint {
    ($($arg:tt)*) => {{
        crate::terminal_output::write_stderr(format_args!($($arg)*), false)
    }};
}

macro_rules! eprintln {
    () => {{ crate::terminal_output::write_stderr(format_args!(""), true) }};
    ($($arg:tt)*) => {{
        crate::terminal_output::write_stderr(format_args!($($arg)*), true)
    }};
}

mod analyzers;
mod audit;
mod cli;
mod commands;
mod graph;
mod kube;
mod output;
mod teardown;
mod terminal_output;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    commands::run(cli::Args::parse()).await
}

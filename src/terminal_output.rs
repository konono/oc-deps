use std::fmt;
use std::io::{self, IsTerminal, Write};

fn color_enabled(is_terminal: bool) -> bool {
    is_terminal && std::env::var_os("NO_COLOR").is_none()
}

pub(crate) fn strip_ansi_csi(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'[') {
            i += 2;
            while i < bytes.len() {
                let byte = bytes[i];
                i += 1;
                if (0x40..=0x7e).contains(&byte) {
                    break;
                }
            }
        } else {
            output.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8(output).expect("removing ASCII escape sequences preserves UTF-8")
}

fn render(args: fmt::Arguments<'_>, color: bool) -> String {
    let rendered = args.to_string();
    if color {
        rendered
    } else {
        strip_ansi_csi(&rendered)
    }
}

fn write_to(mut writer: impl Write, rendered: &str, newline: bool) {
    let result = if newline {
        writeln!(writer, "{rendered}")
    } else {
        write!(writer, "{rendered}")
    };
    result.expect("failed to write command output");
}

pub(crate) fn write_stdout(args: fmt::Arguments<'_>, newline: bool) {
    let rendered = render(args, color_enabled(io::stdout().is_terminal()));
    write_to(io::stdout().lock(), &rendered, newline);
}

pub(crate) fn write_stderr(args: fmt::Arguments<'_>, newline: bool) {
    let rendered = render(args, color_enabled(io::stderr().is_terminal()));
    write_to(io::stderr().lock(), &rendered, newline);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_sgr_and_erase_line_sequences() {
        let input = "\r\x1b[2K\x1b[1;33mwarning\x1b[0m: 日本語";
        assert_eq!(strip_ansi_csi(input), "\rwarning: 日本語");
    }

    #[test]
    fn leaves_plain_text_unchanged() {
        let input = "plain ✅ output";
        assert_eq!(strip_ansi_csi(input), input);
    }

    #[test]
    fn handles_incomplete_escape_without_panicking() {
        assert_eq!(strip_ansi_csi("before\x1b[31"), "before");
    }

    #[test]
    fn non_terminal_render_has_no_escape_bytes() {
        let rendered = render(format_args!("\x1b[31merror\x1b[0m"), false);
        assert_eq!(rendered, "error");
        assert!(!rendered.contains('\x1b'));
    }

    #[test]
    fn terminal_render_preserves_color() {
        let rendered = render(format_args!("\x1b[32mok\x1b[0m"), true);
        assert_eq!(rendered, "\x1b[32mok\x1b[0m");
    }
}

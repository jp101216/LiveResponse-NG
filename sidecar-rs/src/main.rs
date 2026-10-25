//! lrng-sidecar — the Rust half of Live Response NG.
//!
//! Protocol: read exactly one JSON Request line from stdin, perform the
//! operation, write JSON Response line(s) to stdout, exit. Most ops write one
//! line; scan_memory writes one line per PID, flushed as each finishes. The Go
//! host spawns one process per call (see internal/sidecar). Running as a
//! separate process is deliberate: this binary handles hostile input, and
//! crash isolation keeps a bad sample from taking the agent down with it.

mod contract;
mod memscan;
mod prompts;

use contract::Response;
use std::io::{self, BufRead, Write};

fn main() {
    let mut out = io::stdout().lock();
    let mut emit = |resp: Response| {
        let mut line = serde_json::to_string(&resp).unwrap_or_else(|e| {
            format!(r#"{{"op":"","ok":false,"error":"serialize response: {e}"}}"#)
        });
        line.push('\n');
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    };
    run(&mut emit);
}

fn run(emit: &mut dyn FnMut(Response)) {
    let mut input = String::new();
    match io::stdin().lock().read_line(&mut input) {
        Ok(0) => return emit(Response::err("", "no request on stdin")),
        Ok(_) => {}
        Err(e) => return emit(Response::err("", format!("read stdin: {e}"))),
    }

    let req: contract::Request = match serde_json::from_str(input.trim()) {
        Ok(r) => r,
        Err(e) => return emit(Response::err("", format!("decode request: {e}"))),
    };

    // A panic inside an op (e.g. a pathological sample) is caught and returned
    // as an error line rather than aborting the process. scan_memory also
    // catches per PID so earlier results aren't lost.
    let op = req.op.clone();
    let mut emitted = 0usize;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut counting = |r: Response| {
            emitted += 1;
            emit(r)
        };
        dispatch(req, &mut counting)
    }));
    if result.is_err() {
        emit(Response::err(&op, "sidecar panic contained during op"));
    } else if emitted == 0 {
        emit(Response::err(&op, "op produced no response"));
    }
}

fn dispatch(req: contract::Request, emit: &mut dyn FnMut(Response)) {
    match req.op.as_str() {
        "ping" => emit(Response {
            op: "ping".into(),
            ok: true,
            meta: Some(serde_json::json!({
                "service": "lrng-sidecar",
                "version": env!("CARGO_PKG_VERSION"),
                "capabilities": {
                    "scan_prompts": true,
                    "scan_memory": cfg!(any(windows, target_os = "linux")),
                    "yara": cfg!(feature = "yara"),
                    "memory_heuristics": cfg!(any(windows, target_os = "linux")),
                },
            })),
            ..Default::default()
        }),
        "scan_prompts" => emit(prompts::scan("scan_prompts", &req.path, &req.data)),
        "scan_memory" => memscan::handle(&req, emit),
        other => emit(Response::err(other, format!("unknown op: {other}"))),
    }
}

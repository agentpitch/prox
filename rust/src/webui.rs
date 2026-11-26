#[derive(Clone, Copy, Debug)]
pub struct Asset {
    pub content_type: &'static str,
    pub bytes: &'static [u8],
}

macro_rules! asset {
    ($name:literal, $mime:literal) => {
        Asset {
            content_type: $mime,
            bytes: include_bytes!(concat!("../../internal/webui/dist/", $name)),
        }
    };
}

pub fn static_asset(request_path: &str) -> Option<Asset> {
    let mut components = Vec::new();
    for part in request_path.trim().split('/') {
        match part {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(part),
        }
    }
    let index = asset!("index.html", "text/html; charset=utf-8");
    Some(match components.as_slice() {
        [] | ["index.html"] => index,
        ["styles.css"] => asset!("styles.css", "text/css; charset=utf-8"),
        ["design.css"] => asset!("design.css", "text/css; charset=utf-8"),
        ["app.js"] => asset!("app.js", "text/javascript; charset=utf-8"),
        ["rules-ui.js"] => asset!("rules-ui.js", "text/javascript; charset=utf-8"),
        ["favicon.ico"] => asset!("favicon.ico", "image/x-icon"),
        ["pp_icon_256.png"] => asset!("pp_icon_256.png", "image/png"),
        [.., last] if !last.contains('.') => index,
        _ => return None,
    })
}

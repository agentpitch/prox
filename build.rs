use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

#[path = "rust/src/windivert/identity.rs"]
mod windivert_identity;

fn main() {
    println!("cargo:rerun-if-env-changed=PITCHPROX_VERSION");
    println!("cargo:rerun-if-env-changed=PITCHPROX_WINDIVERT_DRIVER");
    println!("cargo:rustc-check-cfg=cfg(embedded_windivert_driver)");
    const ICON: &str = "assets/pp_icon.ico";
    println!("cargo:rerun-if-changed={ICON}");
    println!("cargo:rerun-if-env-changed=WINDRES");
    println!("cargo:rerun-if-env-changed=RC");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
    {
        let icon = Path::new(&std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join(ICON);
        let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
        embed_driver(&out);
        let rc = out.join("pitchprox.rc");
        std::fs::write(
            &rc,
            format!(
                "LANGUAGE 9, 1\n1 ICON \"{}\"\n",
                icon.to_string_lossy().replace('\\', "/")
            ),
        )
        .expect("write Windows resource script");
        let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
        let resource = out.join(if msvc {
            "pitchprox.res"
        } else {
            "pitchprox-icon.o"
        });
        let mut tool = if msvc {
            let mut tool = Command::new(std::env::var_os("RC").unwrap_or_else(|| "rc.exe".into()));
            tool.arg("/nologo").arg("/fo").arg(&resource).arg(&rc);
            tool
        } else {
            let mut tool =
                Command::new(std::env::var_os("WINDRES").unwrap_or_else(|| "windres".into()));
            tool.arg("-O")
                .arg("coff")
                .arg("-i")
                .arg(&rc)
                .arg("-o")
                .arg(&resource);
            tool
        };
        assert!(
            tool.status()
                .expect("run Windows resource compiler")
                .success(),
            "compile Windows icon resource"
        );
        println!("cargo:rustc-link-arg-bin=pitchProx={}", resource.display());
    }
}

fn embed_driver(out: &Path) {
    use windivert_identity::{DRIVER_NAME, DRIVER_SHA256};

    let Some(path) = std::env::var_os("PITCHPROX_WINDIVERT_DRIVER") else {
        return;
    };
    let path = Path::new(&path);
    println!("cargo:rerun-if-changed={}", path.display());
    let bytes =
        std::fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        DRIVER_SHA256,
        "WinDivert 2.2.2 driver SHA-256 mismatch"
    );
    std::fs::write(out.join(DRIVER_NAME), bytes).expect("embed verified WinDivert driver");
    println!("cargo:rustc-cfg=embedded_windivert_driver");
}

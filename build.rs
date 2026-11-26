use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=PITCHPROX_VERSION");
    const ICON: &str = "assets/pp_icon.ico";
    println!("cargo:rerun-if-changed={ICON}");
    println!("cargo:rerun-if-env-changed=WINDRES");
    println!("cargo:rerun-if-env-changed=RC");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
    {
        let icon = Path::new(&std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join(ICON);
        let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
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

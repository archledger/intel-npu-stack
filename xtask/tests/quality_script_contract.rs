// SPDX-License-Identifier: Apache-2.0

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    fn sorted_names(path: &Path) -> Vec<String> {
        let mut names = fs::read_dir(path)
            .expect("read fixture directory")
            .map(|entry| {
                entry
                    .expect("read fixture entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    #[test]
    fn quality_script_invokes_only_the_offline_gate_commands() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has repository parent");
        let script = repository.join("scripts/check.sh");
        let fixture = tempfile::tempdir().expect("create quality fixture");
        let bin = fixture.path().join("bin");
        let trace = fixture.path().join("trace.log");
        fs::create_dir(&bin).expect("create controlled PATH");
        let cargo = bin.join("cargo");
        fs::write(
            &cargo,
            r#"#!/bin/sh
set -eu
printf 'CARGO_NET_OFFLINE=%s RUSTDOCFLAGS=%s ARGS=' "${CARGO_NET_OFFLINE-}" "${RUSTDOCFLAGS-}" >> "$TRACE_PATH"
printf '%s|' "$@" >> "$TRACE_PATH"
printf '\n' >> "$TRACE_PATH"
"#,
        )
        .expect("write fake cargo");
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755))
            .expect("make fake cargo executable");

        let metadata = fs::metadata(&script).expect("quality script must exist");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o755);

        let output = Command::new(&script)
            .current_dir(fixture.path())
            .env_clear()
            .env("PATH", &bin)
            .env("TRACE_PATH", &trace)
            .output()
            .expect("execute quality script");
        assert!(
            output.status.success(),
            "status: {:?}\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let actual = fs::read_to_string(&trace).expect("read fake cargo trace");
        let expected = concat!(
            "CARGO_NET_OFFLINE=true RUSTDOCFLAGS= ARGS=fmt|--all|--|--check|\n",
            "CARGO_NET_OFFLINE=true RUSTDOCFLAGS= ARGS=clippy|--workspace|--all-targets|--locked|--|-D|warnings|\n",
            "CARGO_NET_OFFLINE=true RUSTDOCFLAGS= ARGS=test|--workspace|--locked|\n",
            "CARGO_NET_OFFLINE=true RUSTDOCFLAGS=-D warnings ARGS=doc|--workspace|--no-deps|--locked|\n",
            "CARGO_NET_OFFLINE=true RUSTDOCFLAGS= ARGS=run|-p|xtask|--locked|--|validate-profiles|profiles|\n",
        );
        assert_eq!(actual, expected);
        assert_eq!(sorted_names(fixture.path()), ["bin", "trace.log"]);
        assert_eq!(sorted_names(&bin), ["cargo"]);
    }
}

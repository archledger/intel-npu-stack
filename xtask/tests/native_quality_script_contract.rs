// SPDX-License-Identifier: Apache-2.0

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    fn repository() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has repository parent")
            .to_path_buf()
    }

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

    fn invoke(script: &Path, path: &Path, arguments: &[&Path]) -> Output {
        Command::new(script)
            .args(arguments)
            .env_clear()
            .env("PATH", path)
            .output()
            .expect("execute native quality script")
    }

    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).expect("write fake executable");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("mark fake executable");
    }

    fn install_fake_tools(bin: &Path) {
        fs::create_dir(bin).expect("create controlled PATH");
        write_executable(
            &bin.join("cmake"),
            r#"#!/bin/sh
set -eu
printf 'cmake|' >> "$TRACE_PATH"
printf '%s|' "$@" >> "$TRACE_PATH"
printf '\n' >> "$TRACE_PATH"
if [ "$1" = "--build" ]; then
  build=$2
  export COMPILER_PATH=/usr/bin
  /usr/bin/mkdir -p "$build"
  printf '%s\n' 'void fixture_dependency(void) {}' > "$build/dependency.c"
  printf '%s\n' 'extern void fixture_dependency(void); int main(void) { fixture_dependency(); return 0; }' > "$build/main.c"
  /usr/bin/cc -fPIC -shared -Wl,-soname,libze_loader.so.1 -o "$build/libze_loader.so.1" "$build/dependency.c"
  /usr/bin/cc -fPIE -pie -Wl,-z,relro,-z,now,--no-as-needed -L"$build" -Wl,-rpath-link,"$build" -o "$build/intel-npu-level-zero-probe" "$build/main.c" -l:libze_loader.so.1
  /usr/bin/cc -fPIC -shared -Wl,-soname,libopenvino.so.2620 -o "$build/libopenvino.so.2620" "$build/dependency.c"
  if [ "${FAKE_BAD_RPATH-}" = 1 ]; then
    extra=-Wl,-rpath,/tmp/forbidden
  else
    extra=
  fi
  /usr/bin/cc -fPIE -pie -Wl,-z,relro,-z,now,--no-as-needed $extra -L"$build" -Wl,-rpath-link,"$build" -o "$build/intel-npu-openvino-probe" "$build/main.c" -l:libopenvino.so.2620
else
  build=
  previous=
  for argument do
    if [ "$previous" = -B ]; then build=$argument; fi
    previous=$argument
  done
  [ -n "$build" ]
  printf '%s\n' configured > "$build/.fake-configured"
fi
"#,
        );
        write_executable(
            &bin.join("ctest"),
            r#"#!/bin/sh
set -eu
printf 'ctest|' >> "$TRACE_PATH"
printf '%s|' "$@" >> "$TRACE_PATH"
printf '\n' >> "$TRACE_PATH"
"#,
        );
    }

    #[test]
    fn native_script_rejects_unsafe_paths_before_invoking_tools() {
        let script = repository().join("scripts/check-native.sh");
        let fixture = tempfile::tempdir().expect("create native gate fixture");
        let bin = fixture.path().join("bin");
        let sdk = fixture.path().join("sdk");
        let build = fixture.path().join("build");
        let nested_build = sdk.join("build");
        let trace = fixture.path().join("trace.log");
        fs::create_dir(&bin).expect("create controlled PATH");
        fs::create_dir(&sdk).expect("create SDK fixture");
        fs::create_dir(&build).expect("create build fixture");
        fs::create_dir(&nested_build).expect("create nested build fixture");
        fs::write(&trace, "").expect("create invocation trace");
        write_executable(
            &bin.join("cmake"),
            "#!/bin/sh\nprintf '%s\\n' invoked >> \"$TRACE_PATH\"\nexit 1\n",
        );

        let metadata = fs::metadata(&script).expect("native quality script must exist");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o755);

        let relative = Path::new("relative");
        let missing = fixture.path().join("missing");
        for arguments in [
            vec![relative, build.as_path()],
            vec![missing.as_path(), build.as_path()],
            vec![sdk.as_path(), relative],
            vec![sdk.as_path(), missing.as_path()],
            vec![sdk.as_path(), sdk.as_path()],
            vec![sdk.as_path(), nested_build.as_path()],
        ] {
            let output = Command::new(&script)
                .args(arguments)
                .env_clear()
                .env("PATH", &bin)
                .env("TRACE_PATH", &trace)
                .output()
                .expect("execute invalid native gate");
            assert!(!output.status.success());
        }

        fs::write(build.join("already-present"), "fixture").expect("make build nonempty");
        assert!(!invoke(&script, &bin, &[&sdk, &build]).status.success());
        assert_eq!(fs::read_to_string(&trace).unwrap(), "");
        assert_eq!(sorted_names(&bin), ["cmake"]);
    }

    #[test]
    fn native_script_runs_only_the_exact_build_gate_and_rejects_rpath() {
        let script = repository().join("scripts/check-native.sh");
        let fixture = tempfile::tempdir().expect("create native gate fixture");
        let bin = fixture.path().join("bin");
        let sdk = fixture.path().join("sdk");
        let build = fixture.path().join("build");
        let trace = fixture.path().join("trace.log");
        fs::create_dir(&sdk).expect("create SDK fixture");
        fs::create_dir(&build).expect("create build fixture");
        fs::write(&trace, "").expect("create trace");
        install_fake_tools(&bin);

        let output = Command::new(&script)
            .args([&sdk, &build])
            .env_clear()
            .env("PATH", &bin)
            .env("TRACE_PATH", &trace)
            .output()
            .expect("execute native quality script");
        assert!(
            output.status.success(),
            "status: {:?}\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let expected = format!(
            "cmake|-S|{}/native|-B|{}|-G|Ninja|-DCMAKE_BUILD_TYPE=Release|-DINTEL_NPU_SDK_PREFIX={}|-DBUILD_TESTING=ON|-DCMAKE_FIND_USE_PACKAGE_REGISTRY=FALSE|-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=FALSE|\ncmake|--build|{}|--config|Release|\nctest|--test-dir|{}|--build-config|Release|--output-on-failure|\n",
            repository().display(),
            build.display(),
            sdk.display(),
            build.display(),
            build.display(),
        );
        assert_eq!(fs::read_to_string(&trace).unwrap(), expected);
        assert_eq!(sorted_names(&sdk), Vec::<String>::new());
        assert_eq!(sorted_names(&bin), ["cmake", "ctest"]);
        assert_eq!(
            sorted_names(fixture.path()),
            ["bin", "build", "sdk", "trace.log"]
        );

        let bad_build = fixture.path().join("bad-build");
        fs::create_dir(&bad_build).expect("create bad build fixture");
        let bad = Command::new(&script)
            .args([&sdk, &bad_build])
            .env_clear()
            .env("PATH", &bin)
            .env("TRACE_PATH", &trace)
            .env("FAKE_BAD_RPATH", "1")
            .output()
            .expect("execute RPATH-negative gate");
        assert!(!bad.status.success());
    }
}

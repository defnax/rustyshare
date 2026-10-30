use std::{env, path::PathBuf};

pub mod config_store;
pub mod ssl_key;

pub fn get_base_dir() -> PathBuf {
    // explicit override, e.g. RETROSHARE_DIR=%APPDATA%\RetroShare
    if let Ok(dir) = env::var("RETROSHARE_DIR") {
        println!("using RETROSHARE_DIR={dir}");
        return PathBuf::from(dir);
    }

    // portable mode: data lives in a "data" folder next to the executable.
    // Enabled by a file called "portable" next to the executable, or by "--portable".
    const DATA_DIR: &str = ".retroshare";
    const DATA_DIR_PORTABLE: &str = "data";
    const PORTABLE_TEST_FILE: &str = "portable";

    let exe_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));
    if let Some(exe_dir) = exe_dir {
        let portable = env::args().any(|a| a == "--portable")
            || exe_dir.join(PORTABLE_TEST_FILE).exists();
        if portable {
            let dir = exe_dir.join(DATA_DIR_PORTABLE);
            println!("portable mode, using {}", dir.display());
            std::fs::create_dir_all(&dir).expect("can't create portable data folder");
            return dir;
        }
    }

    dirs::home_dir()
        .expect("can't find home directory")
        .join(DATA_DIR)
}

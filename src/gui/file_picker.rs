use std::path::PathBuf;
#[cfg(any(test, feature = "testing"))]
use std::sync::Mutex;

pub trait FilePickerProvider: Send + Sync {
    fn pick_file(&self) -> Option<PathBuf>;
    fn pick_directory(&self) -> Option<PathBuf>;
}

#[cfg(feature = "gui-file-transfer")]
pub struct RfdFilePickerProvider;

#[cfg(feature = "gui-file-transfer")]
impl FilePickerProvider for RfdFilePickerProvider {
    fn pick_file(&self) -> Option<PathBuf> {
        rfd::FileDialog::new().pick_file()
    }
    fn pick_directory(&self) -> Option<PathBuf> {
        rfd::FileDialog::new().pick_folder()
    }
}

pub struct NoopFilePickerProvider;

impl FilePickerProvider for NoopFilePickerProvider {
    fn pick_file(&self) -> Option<PathBuf> { None }
    fn pick_directory(&self) -> Option<PathBuf> { None }
}

#[cfg(any(test, feature = "testing"))]
pub struct MockFilePickerProvider {
    pub next_file_path: Mutex<Option<PathBuf>>,
    pub next_dir_path: Mutex<Option<PathBuf>>,
    pub history: Mutex<Vec<&'static str>>,
}

#[cfg(any(test, feature = "testing"))]
impl Default for MockFilePickerProvider {
    fn default() -> Self {
        Self {
            next_file_path: Mutex::new(None),
            next_dir_path: Mutex::new(None),
            history: Mutex::new(Vec::new()),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl FilePickerProvider for MockFilePickerProvider {
    fn pick_file(&self) -> Option<PathBuf> {
        self.history.lock().unwrap().push("pick_file");
        self.next_file_path.lock().unwrap().take()
    }
    fn pick_directory(&self) -> Option<PathBuf> {
        self.history.lock().unwrap().push("pick_directory");
        self.next_dir_path.lock().unwrap().take()
    }
}

pub fn has_invalid_filename_chars(name: &str) -> bool {
    name.contains('/') || name.contains('\\')
}

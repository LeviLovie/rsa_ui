#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "RSA Encryption",
        options,
        Box::new(|_cc| Ok(Box::<App>::default())),
    )
}

struct App {
    interactive: bool,
    error: Option<String>,
    keys: Vec<(String, String, String)>,
    public_key_string: String,
    public_key: Option<rsa::RsaPublicKey>,
    private_key_string: String,
    private_key: Option<rsa::RsaPrivateKey>,
    private_key_show: bool,
}

impl Default for App {
    fn default() -> Self {
        let mut app = Self {
            error: None,
            interactive: true,
            keys: Vec::new(),
            public_key_string: String::new(),
            public_key: None,
            private_key_string: String::new(),
            private_key: None,
            private_key_show: false,
        };
        app.load_keys();
        app
    }
}

impl App {
    fn load_keys(&mut self) {
        let config_file = dirs::config_dir()
            .expect("Failed to get config directory")
            .join("rsa_ui")
            .join("keys.yaml");
        if config_file.exists() {
            let default_keys = ronf::File::new_str(
                "default_keys.yaml",
                ronf::FileFormat::Yaml,
                r#"---
keys:
  - name: "default"
    private_key: ""
    public_key: """#,
            );
            let saved_keys = match ronf::File::from_path_format(
                config_file.into_os_string().into_string().unwrap(),
                ronf::FileFormat::Yaml,
            ) {
                Ok(file) => file,
                Err(_) => {
                    self.error = Some("Failed to load keys. Invalid config file.".to_string());
                    self.interactive = false;
                    return;
                }
            };
            let config = match ronf::Config::builder()
                .add_file(default_keys)
                .load(saved_keys)
                .unwrap()
                .build()
            {
                Ok(config) => config,
                Err(_) => {
                    self.error = Some("Failed to load keys. Invalid config file.".to_string());
                    self.interactive = false;
                    return;
                }
            };
            let keys = match config.get("keys") {
                Some(keys) => keys,
                None => {
                    self.error = Some("Failed to load keys. Invalid config file.".to_string());
                    self.interactive = false;
                    return;
                }
            };
            let keys_vec: Vec<ronf::Value> = match (*keys).clone().try_into() {
                Ok(keys_vec) => keys_vec,
                Err(_) => {
                    self.error = Some("Failed to load keys. Invalid config file.".to_string());
                    self.interactive = false;
                    return;
                }
            };
            for key in keys_vec {
                let name = match key.get("name") {
                    Some(name) => name,
                    None => {
                        self.error = Some("Failed to load keys. Invalid config file.".to_string());
                        self.interactive = false;
                        return;
                    }
                };
                let private_key = match key.get("private_key") {
                    Some(private_key) => private_key,
                    None => {
                        self.error = Some("Failed to load keys. Invalid config file.".to_string());
                        self.interactive = false;
                        return;
                    }
                };
                let public_key = match key.get("public_key") {
                    Some(public_key) => public_key,
                    None => {
                        self.error = Some("Failed to load keys. Invalid config file.".to_string());
                        self.interactive = false;
                        return;
                    }
                };
                self.keys.push((
                    name.to_string()
                        .trim_start_matches("\"")
                        .trim_end_matches("\"")
                        .to_string(),
                    private_key
                        .to_string()
                        .trim_start_matches("\"")
                        .trim_end_matches("\"")
                        .to_string(),
                    public_key
                        .to_string()
                        .trim_start_matches("\"")
                        .trim_end_matches("\"")
                        .to_string(),
                ));
            }
        }
    }

    fn save_keys(&mut self) {
        let config_file = dirs::config_dir()
            .expect("Failed to get config directory")
            .join("rsa_ui")
            .join("keys.yaml");
        if !config_file.exists() {
            std::fs::create_dir_all(config_file.parent().unwrap()).unwrap();
        }
        let mut keys = vec![];
        for (name, private_key, public_key) in &self.keys {
            let mut key: std::collections::HashMap<String, ronf::Value> =
                std::collections::HashMap::new();
            key.insert("name".to_string(), ronf::Value::String(name.to_string()));
            key.insert(
                "private_key".to_string(),
                ronf::Value::String(private_key.to_string()),
            );
            key.insert(
                "public_key".to_string(),
                ronf::Value::String(public_key.to_string()),
            );
            keys.push(ronf::Value::Table(key));
        }
        let mut config = ronf::Config::builder()
            .add_file(ronf::File::new_str(
                "default_keys.yaml",
                ronf::FileFormat::Yaml,
                r#"---
keys:
  - name: "default"
    private_key: ""
    public_key: """#,
            ))
            .build()
            .unwrap();
        config.set("keys", ronf::Value::Array(keys));
        let config_string = config.save(ronf::FileFormat::Yaml).unwrap();
        match std::fs::write(config_file, config_string) {
            Ok(_) => {
                self.error = Some("Keys saved".to_string());
                self.interactive = true;
            }
            Err(_) => {
                self.error = Some("Failed to save keys".to_string());
                self.interactive = false;
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::SidePanel::left("keys").show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.label(egui::RichText::new("Keys").heading());
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.interactive, egui::Button::new("Generate"))
                        .clicked()
                    {
                        let mut rng = rand::thread_rng(); // rand@0.8
                        let bits = 2048;
                        let priv_key =
                            RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
                        let pub_key = RsaPublicKey::from(&priv_key);
                        self.private_key = Some(priv_key);
                        self.public_key = Some(pub_key);
                        self.private_key_string = self
                            .private_key
                            .as_ref()
                            .unwrap()
                            .to_pkcs8_pem(rsa::pkcs1::LineEnding::LF)
                            .expect("failed to convert private key to PEM")
                            .to_string();
                        self.public_key_string = self
                            .public_key
                            .as_ref()
                            .unwrap()
                            .to_public_key_pem(rsa::pkcs1::LineEnding::LF)
                            .expect("failed to convert public key to PEM")
                            .to_string();
                        self.keys.push((
                            "Enter name here".to_string(),
                            self.private_key_string.clone(),
                            self.public_key_string.clone(),
                        ));
                    }
                    if ui
                        .add_enabled(self.interactive, egui::Button::new("Load"))
                        .clicked()
                    {
                        let priv_pem = match pem::parse(self.public_key_string.clone()) {
                            Ok(pem) => Some(pem),
                            Err(_) => {
                                self.error = Some("Invalid PEM format of public key".to_string());
                                self.interactive = false;
                                None
                            }
                        };
                        let pub_pem = match pem::parse(self.private_key_string.clone()) {
                            Ok(pem) => Some(pem),
                            Err(_) => {
                                self.error = Some("Invalid PEM format of private key".to_string());
                                self.interactive = false;
                                None
                            }
                        };
                        if self.interactive {
                            let priv_pem = priv_pem.unwrap();
                            match rsa::RsaPublicKey::from_public_key_der(&priv_pem.contents()) {
                                Ok(key) => {
                                    self.public_key = Some(key);
                                }
                                Err(_) => {
                                    self.error = Some("Invalid public key".to_string());
                                    self.interactive = false;
                                }
                            };
                        }
                        if self.interactive {
                            let pub_pem = pub_pem.unwrap();
                            match rsa::RsaPrivateKey::from_pkcs8_der(&pub_pem.contents()) {
                                Ok(key) => {
                                    self.private_key = Some(key);
                                }
                                Err(_) => {
                                    self.error = Some("Invalid private key".to_string());
                                    self.interactive = false;
                                }
                            };
                        }
                    }
                    if ui
                        .add_enabled(self.public_key.is_some(), egui::Button::new("Clear"))
                        .clicked()
                    {
                        self.public_key = None;
                        self.public_key_string.clear();
                        self.private_key = None;
                        self.private_key_string.clear();
                    }
                });
                ui.checkbox(&mut self.private_key_show, "Show private key");
                ui.separator();
                ui.label("Config");
                if ui
                    .add_enabled(self.interactive, egui::Button::new("Save"))
                    .clicked()
                {
                    self.save_keys();
                    self.error = Some("Keys saved".to_string());
                    self.interactive = false;
                }
                ui.label("Keys");
                egui::Grid::new("keys").show(ui, |ui| {
                    ui.label("Name                             ");
                    ui.end_row();
                    let mut keys_to_delete = vec![];
                    let mut new_priv_key = self.public_key_string.clone();
                    let mut new_pub_key = self.private_key_string.clone();
                    let mut load = false;
                    for (i, (name, priv_key, pub_key)) in self.keys.iter_mut().enumerate() {
                        ui.add_enabled(self.interactive, egui::TextEdit::singleline(name));
                        if ui
                            .add_enabled(self.interactive, egui::Button::new("Delete"))
                            .clicked()
                        {
                            keys_to_delete.push(i);
                        }
                        if ui
                            .add_enabled(self.interactive, egui::Button::new("Load"))
                            .clicked()
                        {
                            new_priv_key = priv_key.clone();
                            new_pub_key = pub_key.clone();
                            load = true;
                        }
                        ui.end_row();
                    }
                    for i in keys_to_delete.iter().rev() {
                        self.keys.remove(*i);
                    }
                    if load {
                        self.private_key_string = new_priv_key;
                        self.public_key_string = new_pub_key;
                        let priv_pem = match pem::parse(self.public_key_string.clone()) {
                            Ok(pem) => Some(pem),
                            Err(_) => {
                                self.error = Some("Invalid PEM format of public key".to_string());
                                self.interactive = false;
                                None
                            }
                        };
                        let pub_pem = match pem::parse(self.private_key_string.clone()) {
                            Ok(pem) => Some(pem),
                            Err(_) => {
                                self.error = Some("Invalid PEM format of private key".to_string());
                                self.interactive = false;
                                None
                            }
                        };
                        if self.interactive {
                            let priv_pem = priv_pem.unwrap();
                            match rsa::RsaPublicKey::from_public_key_der(&priv_pem.contents()) {
                                Ok(key) => {
                                    self.public_key = Some(key);
                                }
                                Err(_) => {
                                    self.error = Some("Invalid public key".to_string());
                                    self.interactive = false;
                                }
                            };
                        }
                        if self.interactive {
                            let pub_pem = pub_pem.unwrap();
                            match rsa::RsaPrivateKey::from_pkcs8_der(&pub_pem.contents()) {
                                Ok(key) => {
                                    self.private_key = Some(key);
                                }
                                Err(_) => {
                                    self.error = Some("Invalid private key".to_string());
                                    self.interactive = false;
                                }
                            };
                        }
                    }
                });
                ui.separator();
                ui.label("Public Key");
                ui.add_sized(
                    [ui.available_size().x, 200.0],
                    egui::TextEdit::multiline(&mut self.public_key_string)
                        .code_editor()
                        .interactive(self.interactive),
                );
                ui.separator();
                ui.label("Private Key");
                ui.add_sized(
                    [ui.available_size().x, 200.0],
                    egui::TextEdit::multiline(&mut self.private_key_string)
                        .code_editor()
                        .password(!self.private_key_show)
                        .interactive(self.interactive),
                );
            });
        });
        if self.error.is_some() {
            let window_size = ctx.screen_rect().size();
            egui::Window::new("Error")
                .vscroll(true)
                .default_size([300.0, 100.0])
                .current_pos([window_size.x / 2.0 - 150.0, window_size.y / 3.0 - 50.0])
                .resizable(false)
                .movable(false)
                .title_bar(false)
                .show(ctx, |ui| {
                    egui::ScrollArea::both().show(ui, |ui| {
                        ui.label(self.error.as_ref().unwrap());
                        if ui.button("OK").clicked() {
                            self.error = None;
                            self.interactive = true;
                        }
                    });
                });
        }
    }
}

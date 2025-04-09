#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
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
    rng: rand::rngs::ThreadRng,
    keys: Vec<(String, String, String)>,
    public_key_string: String,
    public_key: Option<rsa::RsaPublicKey>,
    private_key_string: String,
    private_key: Option<rsa::RsaPrivateKey>,
    private_key_show: bool,
    message: String,
    encrypted_message: String,
}

impl Default for App {
    fn default() -> Self {
        let mut app = Self {
            error: None,
            interactive: true,
            rng: rand::thread_rng(),
            keys: Vec::new(),
            public_key_string: String::new(),
            public_key: None,
            private_key_string: String::new(),
            private_key: None,
            private_key_show: false,
            message: String::new(),
            encrypted_message: String::new(),
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
    type: private
    key: """#,
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
                let type_ = match key.get("type") {
                    Some(type_) => type_,
                    None => {
                        self.error = Some("Failed to load keys. Invalid config file.".to_string());
                        self.interactive = false;
                        return;
                    }
                };
                let key_str = match key.get("key") {
                    Some(private_key) => private_key,
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
                    type_
                        .to_string()
                        .trim_start_matches("\"")
                        .trim_end_matches("\"")
                        .to_string(),
                    key_str
                        .to_string()
                        .trim_start_matches("\"")
                        .trim_end_matches("\"")
                        .trim_end_matches("\n")
                        .trim_end_matches("\r")
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
        for (name, type_, key_str) in &self.keys {
            let mut key: std::collections::HashMap<String, ronf::Value> =
                std::collections::HashMap::new();
            key.insert("name".to_string(), ronf::Value::String(name.to_string()));
            key.insert("type".to_string(), ronf::Value::String(type_.to_string()));
            match type_.as_str() {
                "private" => {
                    key.insert("key".to_string(), ronf::Value::String(key_str.to_string()));
                }
                "public" => {
                    key.insert("key".to_string(), ronf::Value::String(key_str.to_string()));
                }
                _ => {
                    self.error = Some("Invalid key type".to_string());
                    self.interactive = false;
                    return;
                }
            }
            keys.push(ronf::Value::Table(key));
        }
        let mut config = ronf::Config::builder()
            .add_file(ronf::File::new_str(
                "default_keys.yaml",
                ronf::FileFormat::Yaml,
                r#"---
keys:
  - name: "default"
    type: private
    key: """#,
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
                        let bits = 2048;
                        let priv_key = RsaPrivateKey::new(&mut self.rng, bits)
                            .expect("failed to generate a key");
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
                            "New key".to_string(),
                            "private".to_string(),
                            self.private_key_string.clone(),
                        ));
                        self.keys.push((
                            "New key".to_string(),
                            "public".to_string(),
                            self.public_key_string.clone(),
                        ));
                    }
                    if ui
                        .add_enabled(self.interactive, egui::Button::new("Parse keys"))
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
                egui::Grid::new("keys").show(ui, |ui| {
                    let mut keys_to_delete = vec![];
                    let mut key_str = String::new();
                    let mut type_str = String::new();
                    let mut load = false;
                    for (i, (name, type_, key)) in self.keys.iter_mut().enumerate() {
                        ui.add_sized([200.0, 20.0], egui::TextEdit::singleline(name));
                        ui.label(type_.clone());
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
                            if type_ == "private" {
                                key_str = key.clone();
                                type_str = type_.clone();
                                load = true;
                            } else if type_ == "public" {
                                key_str = key.clone();
                                type_str = type_.clone();
                                load = true;
                            } else {
                                self.error = Some("Invalid key type".to_string());
                                self.interactive = false;
                            }
                        }
                        ui.end_row();
                    }
                    for i in keys_to_delete.iter().rev() {
                        self.keys.remove(*i);
                    }
                    if load {
                        if type_str == "private" {
                            self.private_key_string = key_str.clone();
                            let priv_pem = match pem::parse(key_str) {
                                Ok(pem) => Some(pem),
                                Err(_) => {
                                    self.error =
                                        Some("Invalid PEM format of public key".to_string());
                                    self.interactive = false;
                                    None
                                }
                            };
                            if self.interactive {
                                let priv_pem = priv_pem.unwrap();
                                match rsa::RsaPrivateKey::from_pkcs8_der(&priv_pem.contents()) {
                                    Ok(key) => {
                                        self.private_key = Some(key);
                                    }
                                    Err(_) => {
                                        self.error = Some("Invalid private key".to_string());
                                        self.interactive = false;
                                    }
                                };
                            }
                        } else if type_str == "public" {
                            self.public_key_string = key_str.clone();
                            let pub_pem = match pem::parse(key_str) {
                                Ok(pem) => Some(pem),
                                Err(_) => {
                                    self.error =
                                        Some("Invalid PEM format of private key".to_string());
                                    self.interactive = false;
                                    None
                                }
                            };
                            if self.interactive {
                                let pub_pem = pub_pem.unwrap();
                                match rsa::RsaPublicKey::from_public_key_der(&pub_pem.contents()) {
                                    Ok(key) => {
                                        self.public_key = Some(key);
                                    }
                                    Err(_) => {
                                        self.error = Some("Invalid public key".to_string());
                                        self.interactive = false;
                                    }
                                };
                            }
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
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Message");
                if ui
                    .add_enabled(self.interactive, egui::Button::new("Encrypt"))
                    .clicked()
                {
                    if self.public_key.is_none() {
                        self.error = Some("No public key".to_string());
                        self.interactive = false;
                    } else {
                        let public_key = self.public_key.clone().unwrap();
                        let message_data = self.message.as_bytes();
                        let encrypted = match public_key.encrypt(
                            &mut self.rng,
                            Pkcs1v15Encrypt,
                            &message_data[..],
                        ) {
                            Ok(encrypted) => encrypted,
                            Err(_) => {
                                self.error = Some("Failed to encrypt".to_string());
                                self.interactive = false;
                                return;
                            }
                        };
                        self.encrypted_message =
                            base64::Engine::encode(&base64::prelude::BASE64_STANDARD, encrypted);
                    }
                }
            });
            ui.add_sized(
                [ui.available_size().x, 200.0],
                egui::TextEdit::multiline(&mut self.message)
                    .code_editor()
                    .interactive(self.interactive),
            );
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Encrypted Message");
                if ui
                    .add_enabled(self.interactive, egui::Button::new("Decrypt"))
                    .clicked()
                {
                    if self.private_key.is_none() {
                        self.error = Some("No private key".to_string());
                        self.interactive = false;
                    } else {
                        let private_key = self.private_key.clone().unwrap();
                        let encrypted_message = self
                            .encrypted_message
                            .clone()
                            .trim_end_matches("\n")
                            .trim_end_matches("\r")
                            .to_string();
                        let encrypted_data = match base64::Engine::decode(
                            &base64::prelude::BASE64_STANDARD,
                            encrypted_message,
                        ) {
                            Ok(data) => data,
                            Err(_) => {
                                self.error = Some("Invalid base64 format".to_string());
                                self.interactive = false;
                                return;
                            }
                        };
                        let decrypted =
                            match private_key.decrypt(Pkcs1v15Encrypt, &encrypted_data[..]) {
                                Ok(decrypted) => decrypted,
                                Err(_) => {
                                    self.error = Some("Failed to decrypt".to_string());
                                    self.interactive = false;
                                    return;
                                }
                            };
                        self.message = String::from_utf8(decrypted).unwrap();
                    }
                }
            });
            ui.add_sized(
                [ui.available_size().x, 200.0],
                egui::TextEdit::multiline(&mut self.encrypted_message)
                    .code_editor()
                    .interactive(self.interactive),
            );
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

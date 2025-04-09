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
    public_key_string: String,
    public_key: Option<rsa::RsaPublicKey>,
    private_key_string: String,
    private_key: Option<rsa::RsaPrivateKey>,
    private_key_show: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            error: None,
            interactive: true,
            public_key_string: String::new(),
            public_key: None,
            private_key_string: String::new(),
            private_key: None,
            private_key_show: false,
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

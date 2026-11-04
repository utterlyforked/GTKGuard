mod backend;

use adw::prelude::*;
use backend::{Secret, SudoError};
use gtk::{gio, glib};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

const APP_ID: &str = "io.github.utterlyforked.GtkGuard";
/// How long the sudo password stays in memory after its last successful use.
const PASSWORD_TTL: Duration = Duration::from_secs(300);

struct Row {
    name: String,
    row: adw::SwitchRow,
}

struct Ui {
    window: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    stack: gtk::Stack,
    group: adw::PreferencesGroup,
    hero: adw::StatusPage,
    rows: RefCell<Vec<Row>>,
    /// True while any privileged operation is in flight. Only one runs at a time.
    busy: Cell<bool>,
    /// True while we change switches programmatically, so handlers ignore it.
    updating: Cell<bool>,
    password: RefCell<Option<(Secret, Instant)>>,
}

fn main() -> glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run()
}

const CSS: &str = "
.hero.connected image { color: @success_color; }
.hero.disconnected image { opacity: 0.45; }
";

#[allow(deprecated)]
fn load_css() {
    let provider = gtk::CssProvider::new();
    provider.load_from_data(CSS);
    if let Some(display) = gtk::gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

fn build_ui(app: &adw::Application) {
    load_css();

    // --- empty state ---
    let import_big = gtk::Button::builder()
        .label("Import config…")
        .halign(gtk::Align::Center)
        .css_classes(["suggested-action", "pill"])
        .build();
    let empty = adw::StatusPage::builder()
        .icon_name("network-vpn-symbolic")
        .title("No tunnels yet")
        .description("Import a WireGuard .conf file to get started.")
        .child(&import_big)
        .build();

    // --- tunnel list ---
    let group = adw::PreferencesGroup::new();
    let hero = adw::StatusPage::builder().css_classes(["compact", "hero"]).build();
    let content = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(12).build();
    content.append(&hero);
    content.append(&group);
    let clamp = adw::Clamp::builder()
        .maximum_size(500)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .child(&content)
        .build();
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&clamp)
        .build();

    let stack = gtk::Stack::new();
    stack.add_named(&empty, Some("empty"));
    stack.add_named(&scroll, Some("list"));

    let toasts = adw::ToastOverlay::new();
    toasts.set_child(Some(&stack));

    // --- header ---
    let import_small = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("Import config")
        .build();
    let header = adw::HeaderBar::new();
    header.pack_start(&import_small);

    let view = adw::ToolbarView::new();
    view.add_top_bar(&header);
    view.set_content(Some(&toasts));

    // Fixed size => niri opens it as a floating window.
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("GTKGuard")
        .default_width(420)
        .default_height(460)
        .resizable(false)
        .content(&view)
        .build();

    let ui = Rc::new(Ui {
        window,
        toasts,
        stack,
        group,
        hero,
        rows: RefCell::new(Vec::new()),
        busy: Cell::new(false),
        updating: Cell::new(false),
        password: RefCell::new(None),
    });

    for b in [&import_big, &import_small] {
        let ui = ui.clone();
        b.connect_clicked(move |_| {
            let ui = ui.clone();
            glib::spawn_future_local(async move { import_flow(&ui).await });
        });
    }

    // Forget the password when the window closes.
    {
        let ui2 = ui.clone();
        ui.window.connect_close_request(move |_| {
            *ui2.password.borrow_mut() = None;
            glib::Propagation::Proceed
        });
    }

    // Reflect external changes (e.g. `wg-quick` run elsewhere).
    {
        let weak = Rc::downgrade(&ui);
        glib::timeout_add_seconds_local(3, move || match weak.upgrade() {
            Some(ui) => {
                refresh(&ui);
                glib::ControlFlow::Continue
            }
            None => glib::ControlFlow::Break,
        });
    }

    rebuild(&ui);
    ui.window.present();
}

// ---------- list ----------

fn rebuild(ui: &Rc<Ui>) {
    for r in ui.rows.borrow_mut().drain(..) {
        ui.group.remove(&r.row);
    }
    let names = backend::load_names();
    for name in names {
        let row = adw::SwitchRow::builder().title(name.as_str()).build();
        let weak = Rc::downgrade(ui);
        let n = name.clone();
        row.connect_active_notify(move |row| {
            if let Some(ui) = weak.upgrade() {
                on_toggle(&ui, &n, row);
            }
        });
        ui.group.add(&row);
        ui.rows.borrow_mut().push(Row { name, row });
    }
    let page = if ui.rows.borrow().is_empty() { "empty" } else { "list" };
    ui.stack.set_visible_child_name(page);
    refresh(ui);
}

fn refresh(ui: &Rc<Ui>) {
    if ui.busy.get() {
        return; // an operation owns the UI until it finishes
    }
    ui.updating.set(true);
    let mut connected: Option<String> = None;
    for r in ui.rows.borrow().iter() {
        let up = backend::is_up(&r.name);
        if r.row.is_active() != up {
            r.row.set_active(up);
        }
        r.row.set_sensitive(true);
        r.row.set_subtitle(if up { "Connected" } else { "Disconnected" });
        if up && connected.is_none() {
            connected = Some(r.name.clone());
        }
    }
    ui.updating.set(false);
    update_hero(ui, connected.as_deref());
}

/// The big graphic at the top: tinted icon when connected, dimmed when not, spinner while working.
fn update_hero(ui: &Rc<Ui>, connected: Option<&str>) {
    let hero = &ui.hero;
    if ui.busy.get() {
        hero.set_paintable(Some(&adw::SpinnerPaintable::new(Some(hero))));
        hero.set_title("Working…");
        hero.set_description(Some("This can take a few seconds"));
        hero.remove_css_class("connected");
        hero.remove_css_class("disconnected");
        return;
    }
    match connected {
        Some(name) => {
            hero.set_icon_name(Some("network-vpn-symbolic"));
            hero.set_title("Connected");
            hero.set_description(Some(name));
            hero.remove_css_class("disconnected");
            hero.add_css_class("connected");
        }
        None => {
            hero.set_icon_name(Some("network-vpn-disconnected-symbolic"));
            hero.set_title("Not connected");
            hero.set_description(Some("Switch a tunnel on to connect"));
            hero.remove_css_class("connected");
            hero.add_css_class("disconnected");
        }
    }
}

fn set_all_sensitive(ui: &Rc<Ui>, on: bool) {
    for r in ui.rows.borrow().iter() {
        r.row.set_sensitive(on);
    }
}

fn on_toggle(ui: &Rc<Ui>, name: &str, row: &adw::SwitchRow) {
    if ui.updating.get() {
        return;
    }
    let want = row.is_active();
    if want == backend::is_up(name) {
        return;
    }
    if ui.busy.get() {
        // Shouldn't happen (rows are insensitive while busy), but never run two operations at once.
        ui.updating.set(true);
        row.set_active(!want);
        ui.updating.set(false);
        return;
    }

    // Only one tunnel at a time: connecting this one first brings any other that is up down.
    let others: Vec<String> = if want {
        ui.rows
            .borrow()
            .iter()
            .filter(|r| r.name != name && backend::is_up(&r.name))
            .map(|r| r.name.clone())
            .collect()
    } else {
        Vec::new()
    };

    ui.busy.set(true);
    set_all_sensitive(ui, false);
    for r in ui.rows.borrow().iter() {
        if r.name == name {
            r.row.set_subtitle(if want { "Connecting…" } else { "Disconnecting…" });
        } else if others.contains(&r.name) {
            r.row.set_subtitle("Disconnecting…");
        }
    }
    update_hero(ui, None);

    let ui = ui.clone();
    let name = name.to_string();
    glib::spawn_future_local(async move {
        let (n, o) = (name.clone(), others);
        // One privileged job, so one password prompt: drop the others, then switch this one.
        let res = with_sudo(&ui, move |pw| {
            for other in &o {
                backend::set_tunnel(pw, other, false)?;
            }
            backend::set_tunnel(pw, &n, want)
        })
        .await;
        ui.busy.set(false);
        if let Some(Err(msg)) = res {
            let heading = if want { "Couldn't connect" } else { "Couldn't disconnect" };
            alert(&ui, heading, &msg).await;
        }
        refresh(&ui);
    });
}

// ---------- dialogs ----------

async fn alert(ui: &Rc<Ui>, heading: &str, body: &str) {
    let d = adw::AlertDialog::builder().heading(heading).body(body).build();
    d.add_response("ok", "OK");
    d.set_default_response(Some("ok"));
    d.set_close_response("ok");
    d.choose_future(Some(&ui.window)).await;
}

async fn get_password(ui: &Rc<Ui>, retry: bool) -> Option<Secret> {
    if !retry {
        if let Some((s, t)) = &*ui.password.borrow() {
            if t.elapsed() < PASSWORD_TTL {
                return Some(s.clone());
            }
        }
    }
    let entry = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .activates_default(true)
        .build();
    let body = if retry {
        "Incorrect password. Try again."
    } else {
        "Enter your password to manage WireGuard tunnels."
    };
    let d = adw::AlertDialog::builder()
        .heading("Authentication required")
        .body(body)
        .extra_child(&entry)
        .build();
    d.add_responses(&[("cancel", "Cancel"), ("ok", "Authenticate")]);
    d.set_default_response(Some("ok"));
    d.set_close_response("cancel");
    d.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
    entry.grab_focus();

    if d.choose_future(Some(&ui.window)).await != "ok" {
        return None;
    }
    let s = Secret::new(entry.text().as_str());
    entry.set_text("");
    if s.is_empty() { None } else { Some(s) }
}

/// Run a privileged operation on a worker thread, prompting for the password as needed.
/// `None` = cancelled; `Some(Err(msg))` = ran but failed.
async fn with_sudo<T, F>(ui: &Rc<Ui>, f: F) -> Option<Result<T, String>>
where
    T: Send + 'static,
    F: Fn(&Secret) -> Result<T, SudoError> + Send + Sync + 'static,
{
    let f = Arc::new(f);
    let mut retry = false;
    loop {
        let pw = get_password(ui, retry).await?;
        let (f2, pw2) = (f.clone(), pw.clone());
        let result = gio::spawn_blocking(move || f2(&pw2)).await.ok()?;
        match result {
            Err(SudoError::BadPassword) => {
                *ui.password.borrow_mut() = None;
                retry = true;
            }
            Ok(v) => {
                *ui.password.borrow_mut() = Some((pw, Instant::now()));
                return Some(Ok(v));
            }
            Err(SudoError::Failed(m)) => {
                *ui.password.borrow_mut() = Some((pw, Instant::now()));
                return Some(Err(m));
            }
        }
    }
}

// ---------- import ----------

async fn import_flow(ui: &Rc<Ui>) {
    if ui.busy.get() {
        return;
    }
    let filter = gtk::FileFilter::new();
    filter.set_name(Some("WireGuard configs (*.conf)"));
    filter.add_pattern("*.conf");
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&filter);

    let dialog = gtk::FileDialog::builder()
        .title("Import WireGuard configs")
        .modal(true)
        .filters(&filters)
        .default_filter(&filter)
        .build();
    if let Some(home) = std::env::var_os("HOME") {
        dialog.set_initial_folder(Some(&gio::File::for_path(
            std::path::PathBuf::from(home).join("Downloads"),
        )));
    }

    let Ok(files) = dialog.open_multiple_future(Some(&ui.window)).await else {
        return; // cancelled
    };

    for i in 0..files.n_items() {
        let Some(file) = files.item(i).and_downcast::<gio::File>() else { continue };
        let Some(path) = file.path() else { continue };
        let label = path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();

        let text = match backend::read_conf(&path).and_then(|t| backend::validate_conf(&t).map(|_| t)) {
            Ok(t) => t,
            Err(e) => {
                alert(ui, &format!("Can't import {label}"), &e).await;
                continue;
            }
        };

        let stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let Some(name) = ask_name(ui, &label, backend::sanitize_name(&stem)).await else {
            continue;
        };

        let (n, t) = (name.clone(), text);
        ui.busy.set(true);
        let res = with_sudo(ui, move |pw| backend::install_conf(pw, &n, &t)).await;
        ui.busy.set(false);
        match res {
            None => return, // password prompt cancelled: stop the whole import
            Some(Err(msg)) => {
                alert(ui, &format!("Couldn't import {label}"), &msg).await;
            }
            Some(Ok(())) => {
                let mut names = backend::load_names();
                names.push(name.clone());
                if let Err(e) = backend::save_names(&names) {
                    alert(ui, "Imported, but couldn't save the tunnel list", &e.to_string()).await;
                }
                rebuild(ui);
                ui.toasts.add_toast(adw::Toast::new(&format!("Imported {name}")));
                offer_delete_original(ui, &path, &label).await;
            }
        }
    }
}

async fn ask_name(ui: &Rc<Ui>, label: &str, suggested: String) -> Option<String> {
    let mut name = suggested;
    let mut msg = format!(
        "Name for the tunnel from “{label}”. Up to {} characters: letters, digits and _ = + . -",
        backend::MAX_NAME
    );
    loop {
        let entry = gtk::Entry::builder().text(name.as_str()).activates_default(true).build();
        let d = adw::AlertDialog::builder()
            .heading("Tunnel name")
            .body(msg.as_str())
            .extra_child(&entry)
            .build();
        d.add_responses(&[("skip", "Skip"), ("ok", "Import")]);
        d.set_default_response(Some("ok"));
        d.set_close_response("skip");
        d.set_response_appearance("ok", adw::ResponseAppearance::Suggested);

        if d.choose_future(Some(&ui.window)).await != "ok" {
            return None;
        }
        name = entry.text().to_string();
        if !backend::is_valid_name(&name) {
            msg = format!(
                "“{name}” isn't valid. Use 1–{} characters from letters, digits and _ = + . - (not starting with “-”).",
                backend::MAX_NAME
            );
        } else if ui.rows.borrow().iter().any(|r| r.name == name) {
            msg = format!("A tunnel called “{name}” is already in the list. Pick another name.");
        } else {
            return Some(name);
        }
    }
}

async fn offer_delete_original(ui: &Rc<Ui>, path: &std::path::Path, label: &str) {
    let d = adw::AlertDialog::builder()
        .heading("Delete the original file?")
        .body(format!(
            "“{label}” contains your private key and may be readable by other users. \
             The imported copy is root-only."
        ))
        .build();
    d.add_responses(&[("keep", "Keep"), ("delete", "Delete")]);
    d.set_default_response(Some("keep"));
    d.set_close_response("keep");
    d.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
    if d.choose_future(Some(&ui.window)).await == "delete" {
        match std::fs::remove_file(path) {
            Ok(()) => ui.toasts.add_toast(adw::Toast::new("Original deleted")),
            Err(e) => alert(ui, "Couldn't delete the file", &e.to_string()).await,
        }
    }
}

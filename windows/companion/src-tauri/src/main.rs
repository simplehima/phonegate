// Release builds are GUI apps: no console window behind the companion.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    phonegate_companion::run();
}

//! Renders the offline challenge as a black-on-white pixel grid (drawn into an HBITMAP by the
//! credential for the tile image slot).

use qrcode::{Color, EcLevel, QrCode};

pub struct Pixels {
    pub size: usize,
    /// Row-major, `true` = dark.
    pub dark: Vec<bool>,
}

/// Renders `text` with a 4-module quiet zone, scaled to roughly `target` pixels.
pub fn render(text: &str, target: usize) -> Option<Pixels> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L).ok()?;
    let modules = code.width();
    let colors = code.to_colors();
    let quiet = 4;
    let total = modules + 2 * quiet;
    let scale = (target / total).max(2);
    let size = total * scale;
    let mut dark = vec![false; size * size];
    for y in 0..modules {
        for x in 0..modules {
            if colors[y * modules + x] == Color::Dark {
                for dy in 0..scale {
                    let row = (y + quiet) * scale + dy;
                    let start = row * size + (x + quiet) * scale;
                    dark[start..start + scale].fill(true);
                }
            }
        }
    }
    Some(Pixels { size, dark })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_offline_challenge_sized_payload() {
        // Realistic PGO1 payload length (~340 chars) must fit and scale to the target.
        let text = format!("PGO1:{}", "A".repeat(335));
        let p = render(&text, 420).unwrap();
        assert!(p.size >= 300 && p.size <= 420 + 200, "size {}", p.size);
        assert_eq!(p.dark.len(), p.size * p.size);
        // Quiet zone is light.
        assert!(!p.dark[0] && !p.dark[p.size - 1]);
        assert!(p.dark.iter().any(|d| *d));
    }
}

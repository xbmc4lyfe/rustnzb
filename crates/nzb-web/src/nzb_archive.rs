//! Unpacking of compressed NZB uploads.
//!
//! Shared by the native `POST /api/queue/add` / add-url handlers and the
//! SABnzbd-compatible `addfile` / `addurl` modes, so every entry point accepts
//! the same archive formats with the same decompression limits.

use std::io::{Cursor, Read as _};

use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;

/// Upper bound on the decompressed size of an uploaded NZB archive, to stop
/// decompression bombs.
pub const MAX_NZB_DECOMPRESSED_BYTES: u64 = 100 * 1024 * 1024;

/// Extract NZB files from an uploaded file, chosen by its extension:
/// `.gz` and `.bz2` hold a single NZB, `.zip` may hold several (every `.nzb`
/// entry is returned). Anything else is returned as-is.
pub fn extract_nzbs(file_name: &str, data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, anyhow::Error> {
    let lower = file_name.to_lowercase();

    // .nzb.gz or .gz containing an nzb
    if lower.ends_with(".gz") {
        let decompressed = read_limited(GzDecoder::new(data), "gzip")?;
        return Ok(vec![(strip_extension(file_name, ".gz"), decompressed)]);
    }

    // .nzb.bz2 or .bz2 containing an nzb
    if lower.ends_with(".bz2") {
        let decompressed = read_limited(BzDecoder::new(data), "bzip2")?;
        return Ok(vec![(strip_extension(file_name, ".bz2"), decompressed)]);
    }

    // .zip archive — extract all .nzb files inside
    if lower.ends_with(".zip") {
        let cursor = Cursor::new(data);
        let mut archive = zip::ZipArchive::new(cursor)
            .map_err(|e| anyhow::anyhow!("Failed to read zip archive: {e}"))?;
        let mut nzbs = Vec::new();
        let mut total_uncompressed = 0u64;
        for i in 0..archive.len() {
            let mut entry = archive
                .by_index(i)
                .map_err(|e| anyhow::anyhow!("Zip entry error: {e}"))?;
            let entry_name = entry.name().to_string();
            if entry_name.to_lowercase().ends_with(".nzb") {
                total_uncompressed = total_uncompressed
                    .checked_add(entry.size())
                    .ok_or_else(|| anyhow::anyhow!("Zip archive size overflow"))?;
                if total_uncompressed > MAX_NZB_DECOMPRESSED_BYTES {
                    anyhow::bail!(
                        "Decompressed NZB exceeds the {} MB limit",
                        MAX_NZB_DECOMPRESSED_BYTES / 1024 / 1024
                    );
                }

                let mut buf = Vec::new();
                entry
                    .by_ref()
                    .take(MAX_NZB_DECOMPRESSED_BYTES + 1)
                    .read_to_end(&mut buf)
                    .map_err(|e| anyhow::anyhow!("Failed to read zip entry '{entry_name}': {e}"))?;
                if buf.len() as u64 > MAX_NZB_DECOMPRESSED_BYTES {
                    anyhow::bail!(
                        "Decompressed NZB exceeds the {} MB limit",
                        MAX_NZB_DECOMPRESSED_BYTES / 1024 / 1024
                    );
                }
                nzbs.push((entry_name, buf));
            }
        }
        if nzbs.is_empty() {
            anyhow::bail!("No .nzb files found in zip archive '{file_name}'");
        }
        return Ok(nzbs);
    }

    // Plain .nzb or unrecognized — pass through as-is
    Ok(vec![(file_name.to_string(), data.to_vec())])
}

/// Decompress a single-file stream, failing past the size limit.
fn read_limited(decoder: impl std::io::Read, format: &str) -> Result<Vec<u8>, anyhow::Error> {
    let mut decompressed = Vec::new();
    decoder
        .take(MAX_NZB_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut decompressed)
        .map_err(|e| anyhow::anyhow!("Failed to decompress {format}: {e}"))?;
    if decompressed.len() as u64 > MAX_NZB_DECOMPRESSED_BYTES {
        anyhow::bail!(
            "Decompressed NZB exceeds the {} MB limit",
            MAX_NZB_DECOMPRESSED_BYTES / 1024 / 1024
        );
    }
    Ok(decompressed)
}

/// Drop a (case-insensitive) extension that `file_name` is known to end with.
fn strip_extension(file_name: &str, extension: &str) -> String {
    file_name[..file_name.len() - extension.len()].to_string()
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    const NZB: &[u8] = br#"<nzb><file subject="ok" /></nzb>"#;

    #[test]
    fn gzip_and_bzip2_unwrap_a_single_nzb() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(NZB).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(
            extract_nzbs("Show.NZB.GZ", &gz).unwrap(),
            vec![("Show.NZB".to_string(), NZB.to_vec())]
        );

        let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        bz.write_all(NZB).unwrap();
        let bz = bz.finish().unwrap();
        assert_eq!(
            extract_nzbs("Show.nzb.bz2", &bz).unwrap(),
            vec![("Show.nzb".to_string(), NZB.to_vec())]
        );
    }

    #[test]
    fn plain_nzb_passes_through() {
        assert_eq!(
            extract_nzbs("plain.nzb", NZB).unwrap(),
            vec![("plain.nzb".to_string(), NZB.to_vec())]
        );
    }
}

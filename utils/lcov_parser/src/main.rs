//! lcov2json – LCOV → delta JSON with rolling bitmap
//!
//!   $ lcov2json --bitmap hitmap.bin a.info b.info -o delta.json

use anyhow::{Context, Result};
use bincode;
use bstr::ByteSlice; // fast line splitting
use clap::Parser;
use memmap2::Mmap;
use mimalloc::MiMalloc;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rayon::prelude::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/* ---------- CLI ---------- */

#[derive(Parser, Debug)]
#[command(author, version, about = "LCOV → delta JSON with rolling bitmap")]
struct Cli {
    /// LCOV .info inputs
    #[arg(required = true, value_name = "INPUT", num_args = 1..)]
    inputs: Vec<PathBuf>,

    /// Where the delta JSON goes
    #[arg(short, long, value_name = "OUT")]
    out: PathBuf,

    /// Binary bitmap file (read then update)
    #[arg(short = 'b', long, value_name = "BITMAP")]
    bitmap: PathBuf,
}

/* ---------- type aliases ---------- */

type LinesMap = HashMap<String, Vec<u32>>; // {file → [hit lines]}
type BitmapMap = HashMap<String, BigUint>; // same as before

/* ---------- helpers ---------- */

fn load_bitmap(path: &PathBuf) -> Result<BitmapMap> {
    let mut buf = Vec::<u8>::new();
    if let Ok(mut f) = File::open(path) {
        f.read_to_end(&mut buf)?;
    }
    if buf.is_empty() {
        return Ok(HashMap::new());
    }
    let raw: Vec<(String, Vec<u8>)> =
        bincode::deserialize(&buf).with_context(|| format!("decode bitmap {}", path.display()))?;
    Ok(raw
        .into_iter()
        .map(|(k, v)| (k, BigUint::from_bytes_be(&v)))
        .collect())
}

fn save_bitmap(path: &PathBuf, bm: &BitmapMap) -> Result<()> {
    let serialisable: Vec<(String, Vec<u8>)> = bm
        .iter()
        .map(|(k, v)| (k.clone(), v.to_bytes_be()))
        .collect();
    let data = bincode::serialize(&serialisable)?;
    let mut f = File::create(path)?;
    f.write_all(&data)?;
    Ok(())
}

#[inline]
fn has_new_bits(bm: &BigUint, old: &BigUint) -> bool {
    (bm & old) != *bm
}

/* ---------- parse one LCOV report ---------- */

fn parse_lcov(m: &Mmap) -> (LinesMap, BitmapMap) {
    let mut cur_file: Option<String> = None;

    let mut lines_hit: LinesMap = HashMap::new();
    let mut bm_int: BitmapMap = HashMap::new();

    for raw in m.lines() {
        let line = raw.trim_end();

        /* SF:<path> */
        if let Some(path) = line.strip_prefix(b"SF:") {
            cur_file = Some(String::from_utf8_lossy(path).into_owned());
            continue;
        }

        /* DA:<line>,<hits> */
        if let Some(rest) = line.strip_prefix(b"DA:") {
            let (line_part, hit_part) = rest.split_once_str(",").unwrap_or((rest, b""));
            if hit_part == b"0" {
                continue; // not executed
            }
            let lno = match std::str::from_utf8(line_part)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
            {
                Some(v) => v,
                None => continue,
            };
            let file = match &cur_file {
                Some(f) => f.clone(),
                None => continue, // LCOV spec says SF first, but be safe
            };

            /* map {file → [lines]} */
            lines_hit.entry(file.clone()).or_default().push(lno);

            /* bitmap */
            let bm = bm_int.entry(file).or_insert_with(BigUint::zero);
            let mut bit = BigUint::one();
            bit <<= lno as usize;
            *bm |= bit;
        }
    }

    /* make output stable & diff-friendly */
    for v in lines_hit.values_mut() {
        v.sort_unstable();
    }

    (lines_hit, bm_int)
}

/* ---------- main ---------- */

fn main() -> Result<()> {
    let args = Cli::parse();

    /* load rolling bitmap */
    let mut global_bm = load_bitmap(&args.bitmap)?;

    /* parse each LCOV in parallel */
    struct Report {
        key: String,
        lines: LinesMap,
        bm: BitmapMap,
    }

    let reports: Vec<Report> = args
        .inputs
        .par_iter()
        .map(|p| -> Result<Report> {
            let f = File::open(p).with_context(|| format!("open {}", p.display()))?;
            let map = unsafe { Mmap::map(&f) }.with_context(|| format!("mmap {}", p.display()))?;
            let (lines, bm_int) = parse_lcov(&map);
            Ok(Report {
                key: p.display().to_string(),
                lines,
                bm: bm_int,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    /* build delta JSON and merge bitmaps */
    let mut json_out: HashMap<String, Value> = HashMap::new();

    for r in reports {
        /* any new bits vs *current* global? */
        let mut has_new = false;
        for (src, bm) in &r.bm {
            match global_bm.get(src) {
                Some(old) => {
                    if has_new_bits(bm, old) {
                        has_new = true;
                        break;
                    }
                }
                None => {
                    if !bm.is_zero() {
                        has_new = true;
                        break;
                    }
                }
            }
        }

        if has_new {
            json_out.insert(r.key.clone(), json!({ "lines": r.lines }));
        } else {
            json_out.insert(r.key.clone(), json!({}));
        }

        /* merge bitmap */
        for (src, bm) in r.bm {
            global_bm
                .entry(src)
                .and_modify(|old| *old |= &bm)
                .or_insert(bm);
        }
    }

    /* write outputs */
    serde_json::to_writer_pretty(BufWriter::new(File::create(&args.out)?), &json_out)?;
    save_bitmap(&args.bitmap, &global_bm)?;

    Ok(())
}

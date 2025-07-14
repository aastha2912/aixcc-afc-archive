//! jacoco2json – JaCoCo XML → delta JSON with rolling bitmap
//!
//!   $ jacoco2json --bitmap hitmap.bin *.xml -o delta.json

use anyhow::{Context, Result};
use bincode;
use clap::Parser;
use memmap2::Mmap;
use mimalloc::MiMalloc;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use quick_xml::{
    events::{BytesStart, Event},
    Reader,
};
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
#[command(author, version, about = "JaCoCo XML → delta JSON with rolling bitmap")]
struct Cli {
    /// JaCoCo XML inputs
    #[arg(required = true, value_name = "INPUT", num_args = 1..)]
    inputs: Vec<PathBuf>,

    /// Where the delta JSON goes
    #[arg(short, long, value_name = "OUT")]
    out: PathBuf,

    /// Binary bitmap file (read, then updated)
    #[arg(short = 'b', long, value_name = "BITMAP")]
    bitmap: PathBuf,
}

/* ---------- data types ---------- */

type LinesMap = HashMap<String, Vec<u32>>; // NEW: {file → [hit lines]}
type BitmapMap = HashMap<String, BigUint>;

/* ---------- helpers ---------- */

#[inline]
fn attr_val(e: &BytesStart<'_>, key: &[u8]) -> Option<String> {
    for a in e.attributes().with_checks(false) {
        let a = a.ok()?;
        if a.key.as_ref() == key {
            return Some(String::from_utf8_lossy(&a.value).into_owned());
        }
    }
    None
}

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

/* ---------- parse a single XML report ---------- */

fn parse_jacoco(xml: &[u8]) -> (LinesMap, BitmapMap) {
    let mut r = Reader::from_reader(std::io::Cursor::new(xml));
    r.trim_text(true);

    let mut buf = Vec::new();

    let (mut cur_pkg, mut cur_file) = (None::<String>, None::<String>);
    let mut lines_hit: LinesMap = HashMap::new();
    let mut bm_int = HashMap::<String, BigUint>::new();

    loop {
        match r.read_event_into(&mut buf) {
            /* open tags */
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"package" => cur_pkg = attr_val(&e, b"name"),
                b"class" => cur_file = attr_val(&e, b"sourcefilename"),
                b"sourcefile" => {
                    if cur_file.is_none() {
                        cur_file = attr_val(&e, b"name")
                    }
                }
                _ => {}
            },
            /* self-closing tags */
            Ok(Event::Empty(e)) => match e.name().as_ref() {
                b"line" => {
                    if let (Some(pkg), Some(file)) = (cur_pkg.as_ref(), cur_file.as_ref()) {
                        if let (Some(nr), Some(ci)) = (attr_val(&e, b"nr"), attr_val(&e, b"ci")) {
                            if ci != "0" {
                                if let Ok(lno) = nr.parse::<u32>() {
                                    let full = format!("{}/{}", pkg, file);
                                    /* map {file → [lines]} */
                                    lines_hit.entry(full.clone()).or_default().push(lno);
                                    /* bitmap */
                                    let bm = bm_int.entry(full).or_insert_with(BigUint::zero);
                                    let mut bit = BigUint::one();
                                    bit <<= lno as usize;
                                    *bm |= bit;
                                }
                            }
                        }
                    }
                }
                _ => {}
            },
            /* close tags */
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"package" => cur_pkg = None,
                b"class" | b"sourcefile" => cur_file = None,
                _ => {}
            },
            /* finish / misc */
            Ok(Event::Eof) => break,
            Err(e) => panic!("XML parse error: {e}"),
            _ => {}
        }
        buf.clear();
    }

    /* be tidy: sort line lists to make diff-ing easier */
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

    /* parse each XML in parallel */
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
            let (lines, bm_int) = parse_jacoco(&map);
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

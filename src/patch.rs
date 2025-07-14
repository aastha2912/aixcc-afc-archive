// Smith‑Waterman matcher

use ndarray::Array2;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[allow(non_upper_case_globals)]
pub const GAP_CHAR: &[u8] = b"__GAP_CHAR__";
#[allow(non_upper_case_globals)]
pub const NEW_SENTINEL: &[u8] = b"+~NEW~+";

type Score = f64;

// ------------------------- Scorer -----------------------------------------
#[derive(Clone, Debug)]
struct MatchScorer {
    delete_weight: f64,
    match_weight: f64,
    sub_weight: f64,
    max_distance: usize,
    alignment_mismatch: f64,
}

impl Default for MatchScorer {
    fn default() -> Self {
        Self {
            delete_weight: 1.0,
            match_weight: 0.0,
            sub_weight: 1.5,
            max_distance: 5,
            alignment_mismatch: -0.5,
        }
    }
}

impl MatchScorer {
    /// len.bit_length() ** 0.5
    #[inline(always)]
    fn bit_length_sqrt(len: usize) -> f64 {
        if len == 0 {
            1.0
        } else {
            ((usize::BITS - len.leading_zeros()) as f64).sqrt()
        }
    }

    #[inline(always)]
    fn char_score(&self, a: u8, b: u8) -> f64 {
        if a == b {
            return self.match_weight;
        }
        if a.is_ascii_digit() && b.is_ascii_digit() {
            return self.sub_weight / 10.0;
        }
        if a.eq_ignore_ascii_case(&b) {
            return self.sub_weight / 10.0;
        }
        self.sub_weight
    }

    fn line_score(&self, a: &[u8], b: &[u8]) -> Score {
        // (1) identical lines
        if a == b {
            return if a.is_empty() {
                1.0
            } else {
                Self::bit_length_sqrt(a.len())
            };
        }

        // (2) sentinel and empty‑string special cases
        if (a == NEW_SENTINEL && b == GAP_CHAR) || (b == NEW_SENTINEL && a == GAP_CHAR) {
            return 0.01;
        }
        if (a.is_empty() && b == GAP_CHAR) || (b.is_empty() && a == GAP_CHAR) {
            return -0.01;
        }

        // (3) length sanity check
        let cutoff = a.len().min(b.len()).min(self.max_distance);
        if a.len().abs_diff(b.len()) > cutoff {
            return self.alignment_mismatch;
        }

        // (4) strip common prefix – speeds up distance DP
        let common_pref = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
        let (a_tail, b_tail) = (&a[common_pref..], &b[common_pref..]);
        let (n, m) = (a_tail.len(), b_tail.len());

        // (5) Wagner–Fischer edit distance, *maximising* similarity
        let mut dist = vec![0.0; (n + 1) * (m + 1)];
        let idx = |i: usize, j: usize| i * (m + 1) + j;
        for i in 1..=n {
            dist[idx(i, 0)] = self.delete_weight * i as Score;
        }
        for j in 1..=m {
            dist[idx(0, j)] = self.delete_weight * j as Score;
        }
        for i in 1..=n {
            let mut early = true;
            for j in 1..=m {
                let sub = dist[idx(i - 1, j - 1)] + self.char_score(a_tail[i - 1], b_tail[j - 1]);
                let del = dist[idx(i - 1, j)] + self.delete_weight;
                let ins = dist[idx(i, j - 1)] + self.delete_weight;
                let s = sub.max(del.max(ins));
                dist[idx(i, j)] = s;
                if s < cutoff as Score {
                    early = false;
                }
            }
            if early {
                return self.alignment_mismatch;
            }
        }
        let dist_nm = dist[idx(n, m)];
        let factor = (1.0 - dist_nm / self.max_distance as Score).powi(2);
        Self::bit_length_sqrt(n.min(m)) * factor
    }

    #[inline(always)]
    fn gap_penalty(&self, line: &[u8]) -> f64 {
        self.line_score(line, GAP_CHAR)
    }
}

// ------------------------- SW matcher -------------------------------------
struct SWMatcher {
    scorer: MatchScorer,
}
impl SWMatcher {
    fn new() -> Self {
        Self {
            scorer: MatchScorer::default(),
        }
    }

    fn build_matrix<'a>(&self, seq1: &[&'a [u8]], seq2: &[&'a [u8]]) -> Array2<Score> {
        let (n, m) = (seq1.len(), seq2.len());
        let mut mat = Array2::<Score>::zeros((n + 1, m + 1));
        for i in 1..=n {
            for j in 1..=m {
                let match_s =
                    mat[(i - 1, j - 1)] + self.scorer.line_score(seq1[i - 1], seq2[j - 1]);
                let del_s = mat[(i - 1, j)] + self.scorer.gap_penalty(seq1[i - 1]);
                let ins_s = mat[(i, j - 1)] + self.scorer.gap_penalty(seq2[j - 1]);
                mat[(i, j)] = match_s.max(del_s.max(ins_s).max(0.0));
            }
        }
        mat
    }

    fn max_score(mat: &Array2<Score>) -> Score {
        mat.iter().fold(0.0, |acc, &v| acc.max(v))
    }

    fn arg_max(mat: &Array2<Score>) -> (usize, usize) {
        let mut max_val = f64::NEG_INFINITY;
        let mut max_idx = (0, 0);
        for ((i, j), &val) in mat.indexed_iter() {
            if val > max_val {
                max_val = val;
                max_idx = (i, j);
            }
        }
        max_idx
    }

    fn backtrack<'a>(
        &self,
        mat: &Array2<Score>,
        seq1: &[&'a [u8]],
        seq2: &[&'a [u8]],
    ) -> Vec<(Option<usize>, Option<usize>)> {
        let (mut i, mut j) = Self::arg_max(mat);
        let mut path = Vec::<(Option<usize>, Option<usize>)>::new();

        while mat[(i, j)] != 0.0 {
            let match_s = mat[(i - 1, j - 1)] + self.scorer.line_score(seq1[i - 1], seq2[j - 1]);
            let del_s = mat[(i - 1, j)] + self.scorer.gap_penalty(seq1[i - 1]);
            let ins_s = mat[(i, j - 1)] + self.scorer.gap_penalty(seq2[j - 1]);
            let best = match_s.max(del_s.max(ins_s));

            // match > delete > insert
            if (match_s - best).abs() < f64::EPSILON {
                i -= 1;
                j -= 1;
                path.push((Some(i), Some(j)));
            } else if (del_s - best).abs() < f64::EPSILON {
                i -= 1;
                path.push((Some(i), None));
            } else if (ins_s - best).abs() < f64::EPSILON {
                j -= 1;
                path.push((None, Some(j)));
            }
        }

        path.reverse();
        path
    }
}

// ------------------------- Helpers ----------------------------------------
fn split_and_norm(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    let mut cur = Vec::new();
    let mut in_word = false;

    for &b in buf {
        if b == b'\n' {
            if !cur.is_empty() && cur.last() == Some(&b' ') {
                cur.pop();
            }
            lines.push(std::mem::take(&mut cur));
            in_word = false;
        } else if (b as char).is_ascii_whitespace() {
            if in_word {
                cur.push(b' ');
                in_word = false;
            }
        } else {
            cur.push(b);
            in_word = true;
        }
    }

    if !cur.is_empty() {
        if cur.last() == Some(&b' ') {
            cur.pop();
        }
        lines.push(cur);
    }
    lines
}

/// Keep only one "best" Smith-Waterman cell, matching the Python tie-breaker.
pub fn break_smith_waterman_ties(
    mat: &mut Array2<Score>,
    top: Score,
    est: Option<usize>,
    seq2_len: usize,
) -> PyResult<()> {
    let mut winners = mat.iter().filter(|&&v| v == top).count();
    if winners == 1 {
        return Ok(());
    }

    if top < 2.0 {
        return Err(PyValueError::new_err("no good matches found"));
    }

    if let Some(est_line) = est {
        let patch_mid = seq2_len as f64 / 2.0;
        for ((row, _col), val) in mat.indexed_iter_mut() {
            if *val == top {
                let diff = (est_line as f64 - patch_mid) - row as f64;
                if diff.abs() >= 10.0 {
                    *val = 0.0;
                }
            }
        }
    }

    winners = mat.iter().filter(|&&v| v == top).count();
    if winners != 1 {
        return Err(PyValueError::new_err(
            "Context lines did not match OR matched multiple locations. \
            Please double-check the correctness of the context lines \
            and/or provide additional context lines."
        ));
    }
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (a, b, est_line=None))]
pub fn sw_align(
    py: Python<'_>,
    a: &[u8],
    b: &[u8],
    est_line: Option<usize>,
) -> PyResult<Vec<(Option<usize>, Option<usize>)>> {
    py.allow_threads(|| {
        let seq1_vecs = split_and_norm(a);
        let seq2_vecs = split_and_norm(b);

        let seq1: Vec<&[u8]> = seq1_vecs.iter().map(|c| c.as_ref()).collect();
        let seq2: Vec<&[u8]> = seq2_vecs.iter().map(|c| c.as_ref()).collect();
        let matcher = SWMatcher::new();
        let mut mat = matcher.build_matrix(&seq1, &seq2);
        let top_score = SWMatcher::max_score(&mat);
        if top_score < 2.0 {
            return Err(PyValueError::new_err("no good matches found"));
        }
        break_smith_waterman_ties(&mut mat, top_score, est_line, seq2.len())?;
        Ok(matcher.backtrack(&mat, &seq1, &seq2))
    })
}

#[pyclass(get_all)]
#[derive(Debug, Default)]
pub struct Edit {
    file: String,
    lines: (usize, usize),
    old_lines: (usize, usize),
    before: Vec<Vec<u8>>,
    after: Vec<Vec<u8>>,
    old_context: Option<String>,
    new_context: Option<String>,
}

#[pymethods]
impl Edit {
    fn __repr__(&self) -> String {
        format!("{:?}", self)
    }
}

#[pyfunction]
pub fn compute_edit(py: Python<'_>, relpath: String, a: &[u8], b: &[u8]) -> PyResult<Edit> {
    py.allow_threads(move || {
        let old_lines: Vec<&[u8]> = a
            .split_inclusive(|&c| c == b'\n')
            .collect();
        let new_lines: Vec<&[u8]> = b
            .split_inclusive(|&c| c == b'\n')
            .collect();

        // match left-to-right
        let liter = old_lines.iter().enumerate()
            .zip(new_lines.iter());
        let line_start = liter
            .filter_map(|((i, &a), &b)| {
                if a != b { Some(i) } else { None }
            })
            .next();
        let line_start = match line_start {
            Some(line_start) => line_start,
            // no difference?
            None => return Ok(Edit::default()),
        };

        // match right-to-left
        let riter = old_lines.iter().enumerate().rev()
            .zip(new_lines.iter().enumerate().rev());
        let end_opt=
            riter.filter_map(|((oi, &old), (ni, &new))|
                if ni == line_start || oi == line_start || old != new {
                    Some((ni + 1, oi + 1))
                } else {
                    None
                }
            )
            .next();

        let (line_end, old_line_end) = match end_opt {
            Some((a, b)) => (a, b),
            // no difference (but shouldn't be possible as we already hit a change l-to-r)
            None => return Ok(Edit::default()),
        };

        fn join_lines(lines: &[&[u8]]) -> Vec<u8> {
            let mut v = Vec::with_capacity(lines.iter().map(|l| l.len()).sum());
            for line in lines {
                v.extend_from_slice(line);
            }
            v
        }

        // +- 4 lines of context
        let old_a = line_start.saturating_sub(4);
        let old_b = (old_line_end.saturating_add(4)).min(old_lines.len());
        let new_a = line_start.saturating_sub(4);
        let new_b = (line_end.saturating_add(4)).min(new_lines.len());

        let old_context = join_lines(&old_lines[old_a..old_b]);
        let new_context = join_lines(&new_lines[new_a..new_b]);

        let before = old_lines[line_start..old_line_end]
            .iter()
            .map(|&x| x.into())
            .collect();
        let after = new_lines[line_start..line_end]
            .iter()
            .map(|&x| x.into())
            .collect();

        Ok(Edit {
            file: relpath,
            lines: (line_start, line_end),
            before,
            after,
            old_lines: (line_start, old_line_end),
            old_context: Some(String::from_utf8_lossy(&old_context).into()),
            new_context: Some(String::from_utf8_lossy(&new_context).into()),
        })
    })
}

#![allow(non_snake_case)]
use clap::Parser;

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

#[derive(Parser)]
struct Options {
    path: std::path::PathBuf,
}

struct Digest([[u8; 4]; 4]);

impl AsRef<[[u8; 4]; 4]> for Digest {
    fn as_ref(&self) -> &[[u8; 4]; 4] {
        &self.0
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for item in self.as_ref().concat().iter().map(|b| format!("{b:02x}")) {
            write!(f, "{item}")?
        }
        Ok(())
    }
}

#[inline]
fn process_chunk(chunk: &[u8; 64], a0: &mut u32, b0: &mut u32, c0: &mut u32, d0: &mut u32) {
    let mut A = *a0;
    let mut B = *b0;
    let mut C = *c0;
    let mut D = *d0;

    let chunk: &[u32; 16] = unsafe { std::mem::transmute(chunk) };

    // Define a macro for the MD5 operation
    macro_rules! md5_op {
        ($a:expr, $b:expr, $c:expr, $d:expr, $f:expr, $g:expr, $k:expr, $s:expr, $chunk:expr) => {
            let mut F = $f;
            F = F.wrapping_add($a).wrapping_add($k).wrapping_add($chunk[$g]);
            $a = $d;
            $d = $c;
            $c = $b;
            $b = $b.wrapping_add(F.rotate_left($s));
        };
    }

    // Define helper macros for the F functions
    macro_rules! f_func1 {
        ($b:expr, $c:expr, $d:expr) => {
            ($b & $c) | (!$b & $d)
        };
    }

    macro_rules! f_func2 {
        ($b:expr, $c:expr, $d:expr) => {
            ($d & $b) | (!$d & $c)
        };
    }

    macro_rules! f_func3 {
        ($b:expr, $c:expr, $d:expr) => {
            $b ^ $c ^ $d
        };
    }

    macro_rules! f_func4 {
        ($b:expr, $c:expr, $d:expr) => {
            $c ^ ($b | !$d)
        };
    }

    // First round (0-15)
    md5_op!(A, B, C, D, f_func1!(B, C, D), 0, K[0], SHIFTS[0], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 1, K[1], SHIFTS[1], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 2, K[2], SHIFTS[2], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 3, K[3], SHIFTS[3], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 4, K[4], SHIFTS[4], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 5, K[5], SHIFTS[5], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 6, K[6], SHIFTS[6], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 7, K[7], SHIFTS[7], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 8, K[8], SHIFTS[8], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 9, K[9], SHIFTS[9], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 10, K[10], SHIFTS[10], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 11, K[11], SHIFTS[11], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 12, K[12], SHIFTS[12], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 13, K[13], SHIFTS[13], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 14, K[14], SHIFTS[14], chunk);
    md5_op!(A, B, C, D, f_func1!(B, C, D), 15, K[15], SHIFTS[15], chunk);

    // Second round (16-31)
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 16 + 1) % 16,
        K[16],
        SHIFTS[16],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 17 + 1) % 16,
        K[17],
        SHIFTS[17],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 18 + 1) % 16,
        K[18],
        SHIFTS[18],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 19 + 1) % 16,
        K[19],
        SHIFTS[19],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 20 + 1) % 16,
        K[20],
        SHIFTS[20],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 21 + 1) % 16,
        K[21],
        SHIFTS[21],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 22 + 1) % 16,
        K[22],
        SHIFTS[22],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 23 + 1) % 16,
        K[23],
        SHIFTS[23],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 24 + 1) % 16,
        K[24],
        SHIFTS[24],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 25 + 1) % 16,
        K[25],
        SHIFTS[25],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 26 + 1) % 16,
        K[26],
        SHIFTS[26],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 27 + 1) % 16,
        K[27],
        SHIFTS[27],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 28 + 1) % 16,
        K[28],
        SHIFTS[28],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 29 + 1) % 16,
        K[29],
        SHIFTS[29],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 30 + 1) % 16,
        K[30],
        SHIFTS[30],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func2!(B, C, D),
        (5 * 31 + 1) % 16,
        K[31],
        SHIFTS[31],
        chunk
    );

    // Third round (32-47)
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 32 + 5) % 16,
        K[32],
        SHIFTS[32],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 33 + 5) % 16,
        K[33],
        SHIFTS[33],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 34 + 5) % 16,
        K[34],
        SHIFTS[34],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 35 + 5) % 16,
        K[35],
        SHIFTS[35],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 36 + 5) % 16,
        K[36],
        SHIFTS[36],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 37 + 5) % 16,
        K[37],
        SHIFTS[37],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 38 + 5) % 16,
        K[38],
        SHIFTS[38],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 39 + 5) % 16,
        K[39],
        SHIFTS[39],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 40 + 5) % 16,
        K[40],
        SHIFTS[40],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 41 + 5) % 16,
        K[41],
        SHIFTS[41],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 42 + 5) % 16,
        K[42],
        SHIFTS[42],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 43 + 5) % 16,
        K[43],
        SHIFTS[43],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 44 + 5) % 16,
        K[44],
        SHIFTS[44],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 45 + 5) % 16,
        K[45],
        SHIFTS[45],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 46 + 5) % 16,
        K[46],
        SHIFTS[46],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func3!(B, C, D),
        (3 * 47 + 5) % 16,
        K[47],
        SHIFTS[47],
        chunk
    );

    // Fourth round (48-63)
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 48) % 16,
        K[48],
        SHIFTS[48],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 49) % 16,
        K[49],
        SHIFTS[49],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 50) % 16,
        K[50],
        SHIFTS[50],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 51) % 16,
        K[51],
        SHIFTS[51],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 52) % 16,
        K[52],
        SHIFTS[52],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 53) % 16,
        K[53],
        SHIFTS[53],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 54) % 16,
        K[54],
        SHIFTS[54],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 55) % 16,
        K[55],
        SHIFTS[55],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 56) % 16,
        K[56],
        SHIFTS[56],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 57) % 16,
        K[57],
        SHIFTS[57],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 58) % 16,
        K[58],
        SHIFTS[58],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 59) % 16,
        K[59],
        SHIFTS[59],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 60) % 16,
        K[60],
        SHIFTS[60],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 61) % 16,
        K[61],
        SHIFTS[61],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 62) % 16,
        K[62],
        SHIFTS[62],
        chunk
    );
    md5_op!(
        A,
        B,
        C,
        D,
        f_func4!(B, C, D),
        (7 * 63) % 16,
        K[63],
        SHIFTS[63],
        chunk
    );

    *a0 = a0.wrapping_add(A);
    *b0 = b0.wrapping_add(B);
    *c0 = c0.wrapping_add(C);
    *d0 = d0.wrapping_add(D);
}

fn compute_md5<T>(mut reader: T) -> Digest
where
    T: std::io::Read,
{
    let mut a0 = 0x67452301u32;
    let mut b0 = 0xefcdab89u32;
    let mut c0 = 0x98badcfeu32;
    let mut d0 = 0x10325476u32;

    let mut chunk = [0; 64];
    let mut len_bits = 0;

    while let Ok(bytes_read) = reader.read(&mut chunk) {
        len_bits += bytes_read * 8;

        match bytes_read {
            64 => process_chunk(&chunk, &mut a0, &mut b0, &mut c0, &mut d0),
            0..56 => {
                chunk[bytes_read] = 0b10000000;
                chunk[bytes_read + 1..56].fill(0);
                chunk[56..].copy_from_slice(&len_bits.to_le_bytes());
                process_chunk(&mut chunk, &mut a0, &mut b0, &mut c0, &mut d0);
                break;
            }
            56..64 => {
                chunk[bytes_read] = 0b10000000;
                chunk[bytes_read + 1..].fill(0);
                process_chunk(&mut chunk, &mut a0, &mut b0, &mut c0, &mut d0);
                chunk.fill(0);
                chunk[56..].copy_from_slice(&len_bits.to_le_bytes());
                process_chunk(&mut chunk, &mut a0, &mut b0, &mut c0, &mut d0);
                break;
            }
            _ => unreachable!(),
        }
    }

    Digest([
        a0.to_le_bytes(),
        b0.to_le_bytes(),
        c0.to_le_bytes(),
        d0.to_le_bytes(),
    ])
}

fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let mut reader =
        std::io::BufReader::with_capacity(4096 * 8, std::fs::File::open(&options.path)?);
    println!(
        "{hash}  {fname}",
        hash = compute_md5(&mut reader).to_string(),
        fname = options.path.to_str().unwrap()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        assert_eq!(
            compute_md5(std::io::Cursor::new("")).to_string(),
            "d41d8cd98f00b204e9800998ecf8427e".to_string()
        )
    }

    #[test]
    fn brown_fox() {
        assert_eq!(
            compute_md5(std::io::Cursor::new(
                "The quick brown fox jumps over the lazy dog"
            ))
            .to_string(),
            "9e107d9d372bb6826bd81d3542a419d6".to_string()
        )
    }
}

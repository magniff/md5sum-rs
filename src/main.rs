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

    for round in 0..64 {
        let (mut F, g) = match round {
            0..=15 => ((B & C) | (!B & D), round),
            16..=31 => ((D & B) | (!D & C), (5 * round + 1) % 16),
            32..=47 => (B ^ C ^ D, (3 * round + 5) % 16),
            48..=63 => (C ^ (B | !D), (7 * round) % 16),
            _ => unreachable!(),
        };

        F = F
            .wrapping_add(A)
            .wrapping_add(K[round])
            .wrapping_add(chunk[g]);
        A = D;
        D = C;
        C = B;
        B = B.wrapping_add(F.rotate_left(SHIFTS[round]))
    }

    *a0 = a0.wrapping_add(A);
    *b0 = b0.wrapping_add(B);
    *c0 = c0.wrapping_add(C);
    *d0 = d0.wrapping_add(D);
}

fn comptue_md5<T>(mut reader: T) -> Digest
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
    let mut reader = std::io::BufReader::new(std::fs::File::open(&options.path)?);
    println!(
        "{hash}  {fname}",
        hash = comptue_md5(&mut reader).to_string(),
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
            comptue_md5(std::io::Cursor::new("")).to_string(),
            "d41d8cd98f00b204e9800998ecf8427e".to_string()
        )
    }

    #[test]
    fn brown_fox() {
        assert_eq!(
            comptue_md5(std::io::Cursor::new(
                "The quick brown fox jumps over the lazy dog"
            ))
            .to_string(),
            "9e107d9d372bb6826bd81d3542a419d6".to_string()
        )
    }
}

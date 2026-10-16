//! Forward-only physical partition markers and continuation groups.
//! Class tags come from the structural registry, never gzip/name searching.
use crate::{compression::InflatedStream, schema_registry::Registry};
use anyhow::{Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{borrow::Cow, io::Read};

#[derive(Debug, Clone, Serialize)]
pub struct GroupSource {
    pub content_key: Option<[u8; 16]>,
    /// The element count the keyed `ContentMarker` before the group states
    /// (`m_nElementCount`); `None` outside a keyed block.
    pub content_element_count: Option<u32>,
    pub channel: u64,
    pub first_marker_offset: usize,
    pub segment_count: usize,
    pub declared_objects: u64,
    pub declared_body_bytes: u64,
}
#[derive(Debug, Default, Clone, Serialize)]
pub struct Statistics {
    pub segments: usize,
    pub groups: usize,
    pub content_sections: usize,
    pub inflated_bytes: u64,
    pub trailing_padding_bytes: usize,
    pub opaque_terminal_bytes: usize,
    pub opaque_terminal_sha256: String,
}
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| anyhow::anyhow!("partition marker overflow"))?;
        let b = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| anyhow::anyhow!("truncated partition marker at {}", self.pos))?;
        self.pos = end;
        Ok(b)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
}
/// The member of `inflated` at `offset` where it is the whole gzip member
/// `compressed`, as the decoder in [`walk_inflated`] would read it: a header
/// with no optional fields, the DEFLATE stream, then a CRC and ISIZE that
/// match the member, ending at the segment's end, within the group budget.
fn whole_member<'a>(
    inflated: &'a InflatedStream,
    offset: usize,
    compressed: &[u8],
    max_group_bytes: usize,
) -> Option<&'a [u8]> {
    let (member, consumed, crc) = inflated.member_with_crc_at(offset)?;
    let trailer = compressed.get(consumed..)?;
    if compressed.get(3) != Some(&0) || trailer.len() != 8 || member.len() > max_group_bytes {
        return None;
    }
    (trailer[..4] == crc.to_le_bytes() && trailer[4..] == (member.len() as u32).to_le_bytes())
        .then_some(member)
}
/// Walk a checksum-prepared partition. Each callback receives a complete
/// continuation group, not a claimed live element. Maximum reassembled group
/// size is an explicit caller budget. Gzip CRC, ISIZE, boundary, checkback and
/// continuation flags are checked before a group is exposed.
pub fn walk(
    prepared: &[u8],
    registry: &Registry,
    max_group_bytes: usize,
    callback: impl FnMut(&GroupSource, &[u8]) -> Result<()>,
) -> Result<Statistics> {
    walk_inflated(prepared, None, registry, max_group_bytes, callback)
}
/// [`walk`], taking each segment's inflated bytes from `inflated`, the same
/// stream's members inflated once for every reader of the file
/// ([`crate::RevitFile::inflated_partition`]), where it holds them, rather
/// than inflating them again (B82). A member is taken only where it is the
/// whole segment, with a CRC and ISIZE that match it; any other segment is
/// inflated and checked as [`walk`] does.
pub fn walk_inflated(
    prepared: &[u8],
    inflated: Option<&InflatedStream>,
    registry: &Registry,
    max_group_bytes: usize,
    mut callback: impl FnMut(&GroupSource, &[u8]) -> Result<()>,
) -> Result<Statistics> {
    let tags = MarkerTags::new(registry)?;
    walk_framing(
        prepared,
        inflated,
        &tags,
        max_group_bytes,
        Inflate::All,
        &mut |_, _, _| {},
        &mut callback,
    )
}
/// [`walk_inflated`] for a reader of the document's own records: the groups
/// of keyed blocks, the documents of the loaded families (RE-148, RE-163),
/// are not inflated and reach `callback` with no bytes. Their framing is
/// checked all the same, and the statistics count their segments' ISIZE.
pub fn walk_document(
    prepared: &[u8],
    inflated: Option<&InflatedStream>,
    registry: &Registry,
    max_group_bytes: usize,
    mut callback: impl FnMut(&GroupSource, &[u8]) -> Result<()>,
) -> Result<Statistics> {
    let tags = MarkerTags::new(registry)?;
    walk_framing(
        prepared,
        inflated,
        &tags,
        max_group_bytes,
        Inflate::Unkeyed,
        &mut |_, _, _| {},
        &mut callback,
    )
}
/// Where the gzip member of each segment outside every keyed block starts in
/// `prepared`, with its ISIZE: the members of the document's own records, without the
/// documents of the loaded families embedded in keyed blocks (RE-148,
/// RE-163). On a large project those are most of the partition (a Revit 2024
/// project of 1.2 GB: 4.7 of 6.2 GB inflated). The markers are read and
/// checked as [`walk`] does; nothing is inflated.
pub fn document_members(prepared: &[u8], tags: &MarkerTags) -> Result<Vec<(usize, u32)>> {
    let mut members = Vec::new();
    walk_framing(
        prepared,
        None,
        tags,
        usize::MAX,
        Inflate::None,
        &mut |at, keyed, isize| {
            if !keyed {
                members.push((at, isize));
            }
        },
        &mut |_, _| Ok(()),
    )?;
    Ok(members)
}
/// The schema tags of the partition framing markers.
#[derive(Debug, Clone, Copy)]
pub struct MarkerTags {
    content: u16,
    content_key: u16,
    segment: u16,
    checkback: u16,
    /// The 2016 and 2017 schemas have no `SignatureMarker` class and their
    /// partitions write none (#421); it is required only where it is met.
    signature: Option<u16>,
}
impl MarkerTags {
    pub fn new(registry: &Registry) -> Result<Self> {
        let tag = |name: &str| {
            registry
                .named(name)
                .map(|c| c.tag)
                .ok_or_else(|| anyhow::anyhow!("partition schema class absent: {name}"))
        };
        Ok(Self {
            content: tag("ContentMarker")?,
            content_key: tag("ContentKey")?,
            segment: tag("SegmentMarker")?,
            checkback: tag("SegmentCheckback")?,
            signature: registry.named("SignatureMarker").map(|c| c.tag),
        })
    }
}
/// Which segments [`walk_framing`] inflates.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Inflate {
    All,
    /// Those outside every keyed block.
    Unkeyed,
    None,
}
/// The marker walk behind [`walk_inflated`], [`walk_document`] and
/// [`document_members`]. `on_segment` sees where each segment's gzip member
/// starts, whether it lies in a keyed block and its ISIZE; a segment not
/// inflated adds no bytes to its group.
fn walk_framing(
    prepared: &[u8],
    inflated: Option<&InflatedStream>,
    tags: &MarkerTags,
    max_group_bytes: usize,
    inflate: Inflate,
    on_segment: &mut dyn FnMut(usize, bool, u32),
    callback: &mut dyn FnMut(&GroupSource, &[u8]) -> Result<()>,
) -> Result<Statistics> {
    ensure!(max_group_bytes > 0, "zero partition group budget");
    let mut r = Reader {
        bytes: prepared,
        pos: 0,
    };
    r.take(8)?;
    let mut stats = Statistics::default();
    let mut content_key = None;
    let mut content_element_count = None;
    let mut last_size = None;
    let mut active: Option<(GroupSource, Cow<[u8]>)> = None;
    loop {
        let offset = r.pos;
        let next = r.u16()?;
        if next == tags.content {
            ensure!(
                active.is_none(),
                "content boundary interrupts continued segment"
            );
            let token = r.u32()?;
            let count = if token == 0 {
                content_key = None;
                content_element_count = None;
                r.u32()?
            } else {
                ensure!(
                    token == u32::MAX && r.u16()? == tags.content_key,
                    "unsupported content key pointer"
                );
                let count = r.u32()?;
                content_key = Some(r.take(16)?.try_into()?);
                content_element_count = Some(count);
                count
            };
            if token == 0 && count == u32::MAX {
                let tail = &prepared[r.pos..];
                ensure!(
                    tail.len() <= crate::compression::REVIT_STORED_PAGE_BYTES,
                    "partition opaque terminal exceeds one storage page"
                );
                stats.trailing_padding_bytes = tail.iter().take_while(|&&v| v == 0).count();
                stats.opaque_terminal_bytes = tail.len();
                stats.opaque_terminal_sha256 = Sha256::digest(tail)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                return Ok(stats);
            }
            stats.content_sections += 1;
        } else if next == tags.segment {
            let flags = r.u32()?;
            let count = r.u32()?;
            let size = r.u32()?;
            let raw = r.u32()?;
            if size == 0 {
                ensure!(
                    flags == 0 && count == 0 && raw == 0 && active.is_none(),
                    "invalid empty segment marker"
                );
                continue;
            }
            // `m_continuationBits` is `(n << 2) | flags`: flag 1 continues the
            // previous segment, flag 2 continues into the next. `n` is 1 on
            // every segment from Revit 2018 on and 100 or more before, rising
            // through a stream (#421); it is not read beyond being set.
            ensure!(
                flags >> 2 != 0 && size >= 18,
                "unsupported segment flags/size at {offset}"
            );
            let channel = r.u64()?;
            let compressed_at = r.pos;
            let compressed = r.take(size as usize - 8)?;
            // The gzip trailer's ISIZE: the member's inflated length.
            let isize = u32::from_le_bytes(compressed[compressed.len() - 4..].try_into()?);
            on_segment(compressed_at, content_key.is_some(), isize);
            let inflates = match inflate {
                Inflate::All => true,
                Inflate::Unkeyed => content_key.is_none(),
                Inflate::None => false,
            };
            let bytes = if !inflates {
                stats.inflated_bytes += u64::from(isize);
                Cow::Borrowed(&[][..])
            } else {
                let bytes = match inflated.and_then(|stream| {
                    whole_member(stream, compressed_at, compressed, max_group_bytes)
                }) {
                    Some(member) => Cow::Borrowed(member),
                    None => {
                        let mut decoder = flate2::bufread::GzDecoder::new(compressed);
                        let mut bytes = Vec::new();
                        (&mut decoder)
                            .take(max_group_bytes as u64 + 1)
                            .read_to_end(&mut bytes)?;
                        ensure!(
                            bytes.len() <= max_group_bytes,
                            "inflated segment group budget exceeded"
                        );
                        ensure!(
                            decoder.get_ref().is_empty(),
                            "gzip does not consume exact declared segment boundary"
                        );
                        Cow::Owned(bytes)
                    }
                };
                stats.inflated_bytes += bytes.len() as u64;
                bytes
            };
            stats.segments += 1;
            last_size = Some(size);
            let from_previous = flags & 1 != 0;
            let to_next = flags & 2 != 0;
            ensure!(
                from_previous == active.is_some(),
                "segment continuation state mismatch at {offset}"
            );
            if let Some((source, data)) = &mut active {
                ensure!(
                    source.channel == channel && source.content_key == content_key,
                    "continuation channel/content mismatch"
                );
                ensure!(
                    data.len()
                        .checked_add(bytes.len())
                        .is_some_and(|n| n <= max_group_bytes),
                    "reassembled group budget exceeded"
                );
                data.to_mut().extend_from_slice(&bytes);
                source.segment_count += 1;
                source.declared_objects += u64::from(count);
                source.declared_body_bytes += u64::from(raw);
            } else {
                active = Some((
                    GroupSource {
                        content_key,
                        content_element_count,
                        channel,
                        first_marker_offset: offset,
                        segment_count: 1,
                        declared_objects: u64::from(count),
                        declared_body_bytes: u64::from(raw),
                    },
                    bytes,
                ));
            }
            if !to_next {
                let (source, bytes) = active.take().unwrap();
                callback(&source, &bytes)?;
                stats.groups += 1;
            }
        } else if next == tags.checkback {
            ensure!(
                last_size == Some(r.u32()?),
                "segment checkback mismatch at {offset}"
            );
            last_size = None;
        } else if Some(next) == tags.signature {
            ensure!(active.is_none(), "signature interrupts continued segment");
            let count = r.u32()? as usize;
            ensure!(count <= 1_000_000, "partition signature budget exceeded");
            r.take(count)?;
            let units = r.u32()? as usize;
            ensure!(
                units <= 1_000_000,
                "partition signature string budget exceeded"
            );
            let text = r
                .take(units * 2)?
                .chunks_exact(2)
                .map(|s| u16::from_le_bytes([s[0], s[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&text)?;
        } else {
            anyhow::bail!("unsupported partition marker {next} at {offset}");
        }
    }
}

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
/// The checksum-stripped partition read from `pages` (a
/// [`crate::compression::StrippedPages`]) with every keyed block left out:
/// the bytes [`walk`] reads, less the documents of the loaded families
/// (RE-148, RE-163), each block from its keyed `ContentMarker` to the next
/// `ContentMarker`. A group never runs across a content marker, so what is
/// kept walks as the whole stream does, its keyed groups aside. Reads the
/// stream once and holds only what it keeps, at most `max_bytes`; the
/// markers are read as [`walk`] reads them (the kept ones are checked again
/// when walked).
pub fn read_document_stream(
    mut pages: impl Read,
    tags: &MarkerTags,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let keep = |out: &mut Vec<u8>, bytes: &[u8]| -> Result<()> {
        ensure!(
            out.len().saturating_add(bytes.len()) <= max_bytes,
            "partition's own segments exceed {max_bytes} bytes"
        );
        out.extend_from_slice(bytes);
        Ok(())
    };
    let take = |pages: &mut dyn Read, n: usize| -> Result<Vec<u8>> {
        let mut buf = vec![0; n];
        pages.read_exact(&mut buf)?;
        Ok(buf)
    };
    let u16_of = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    let u32_of = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let header = take(&mut pages, 8)?;
    keep(&mut out, &header)?;
    let mut keyed = false;
    loop {
        let tag_bytes = take(&mut pages, 2)?;
        let tag = u16_of(&tag_bytes);
        if tag == tags.content {
            let token = take(&mut pages, 4)?;
            let mut marker = tag_bytes.clone();
            marker.extend_from_slice(&token);
            if u32_of(&token) == 0 {
                let count = take(&mut pages, 4)?;
                marker.extend_from_slice(&count);
                keyed = false;
                keep(&mut out, &marker)?;
                if u32_of(&count) == u32::MAX {
                    // The opaque terminal: at most one storage page.
                    let mut tail = Vec::new();
                    (&mut pages)
                        .take(crate::compression::REVIT_STORED_PAGE_BYTES as u64 + 1)
                        .read_to_end(&mut tail)?;
                    ensure!(
                        tail.len() <= crate::compression::REVIT_STORED_PAGE_BYTES,
                        "partition opaque terminal exceeds one storage page"
                    );
                    keep(&mut out, &tail)?;
                    return Ok(out);
                }
            } else {
                let key = take(&mut pages, 2 + 4 + 16)?;
                ensure!(
                    u32_of(&token) == u32::MAX && u16_of(&key) == tags.content_key,
                    "unsupported content key pointer"
                );
                keyed = true;
            }
        } else if tag == tags.segment {
            let fields = take(&mut pages, 16)?;
            // The channel and the gzip member: `size` bytes after the
            // fields, none for an empty segment.
            let size = u32_of(&fields[8..]) as usize;
            ensure!(size == 0 || size >= 18, "unsupported segment size");
            if keyed {
                let skipped =
                    std::io::copy(&mut (&mut pages).take(size as u64), &mut std::io::sink())?;
                ensure!(skipped == size as u64, "truncated partition segment");
            } else {
                keep(&mut out, &tag_bytes)?;
                keep(&mut out, &fields)?;
                let payload = take(&mut pages, size)?;
                keep(&mut out, &payload)?;
            }
        } else if tag == tags.checkback {
            let size = take(&mut pages, 4)?;
            if !keyed {
                keep(&mut out, &tag_bytes)?;
                keep(&mut out, &size)?;
            }
        } else if Some(tag) == tags.signature {
            let count = take(&mut pages, 4)?;
            let n = u32_of(&count) as usize;
            ensure!(n <= 1_000_000, "partition signature budget exceeded");
            let bytes = take(&mut pages, n)?;
            let units = take(&mut pages, 4)?;
            let u = u32_of(&units) as usize;
            ensure!(u <= 1_000_000, "partition signature string budget exceeded");
            let text = take(&mut pages, u * 2)?;
            if !keyed {
                for part in [&tag_bytes[..], &count, &bytes, &units, &text] {
                    keep(&mut out, part)?;
                }
            }
        } else {
            anyhow::bail!("unsupported partition marker {tag}");
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const TAGS: MarkerTags = MarkerTags {
        content: 0x10,
        content_key: 0x11,
        segment: 0x12,
        checkback: 0x13,
        signature: Some(0x14),
    };

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn content(out: &mut Vec<u8>, key: Option<[u8; 16]>, count: u32) {
        out.extend(TAGS.content.to_le_bytes());
        match key {
            None => {
                out.extend(0u32.to_le_bytes());
                out.extend(count.to_le_bytes());
            }
            Some(key) => {
                out.extend(u32::MAX.to_le_bytes());
                out.extend(TAGS.content_key.to_le_bytes());
                out.extend(count.to_le_bytes());
                out.extend(key);
            }
        }
    }

    /// One group of one segment, then its checkback.
    fn segment(out: &mut Vec<u8>, channel: u64, body: &[u8]) {
        let member = gzip(body);
        let size = member.len() as u32 + 8;
        out.extend(TAGS.segment.to_le_bytes());
        out.extend((1u32 << 2).to_le_bytes());
        out.extend(1u32.to_le_bytes());
        out.extend(size.to_le_bytes());
        out.extend((body.len() as u32).to_le_bytes());
        out.extend(channel.to_le_bytes());
        out.extend(&member);
        out.extend(TAGS.checkback.to_le_bytes());
        out.extend(size.to_le_bytes());
    }

    fn groups(prepared: &[u8]) -> Vec<(Option<[u8; 16]>, u64, Vec<u8>)> {
        let mut out = Vec::new();
        walk_framing(
            prepared,
            None,
            &TAGS,
            1 << 20,
            Inflate::All,
            &mut |_, _, _| {},
            &mut |source, bytes| {
                out.push((source.content_key, source.channel, bytes.to_vec()));
                Ok(())
            },
        )
        .unwrap();
        out
    }

    #[test]
    fn document_stream_leaves_out_the_keyed_blocks() {
        let mut stream = vec![0u8; 8];
        content(&mut stream, None, 2);
        segment(&mut stream, 101, b"project one");
        segment(&mut stream, 102, b"project two");
        content(&mut stream, Some([7; 16]), 1);
        segment(&mut stream, 102, b"family");
        content(&mut stream, None, 1);
        segment(&mut stream, 103, b"project three");
        content(&mut stream, None, u32::MAX);
        stream.extend([0u8; 12]);

        let document = read_document_stream(&stream[..], &TAGS, usize::MAX).unwrap();
        assert!(document.len() < stream.len());
        let unkeyed: Vec<_> = groups(&stream)
            .into_iter()
            .filter(|(key, _, _)| key.is_none())
            .collect();
        assert_eq!(groups(&document), unkeyed);
        assert_eq!(unkeyed.len(), 3);
        // Its members are those document_members finds in the whole stream.
        let inflated = |prepared: &[u8]| {
            let members = document_members(prepared, &TAGS).unwrap();
            crate::compression::InflatedStream::from_members(prepared, &members, usize::MAX)
                .bytes()
                .to_vec()
        };
        assert_eq!(inflated(&document), inflated(&stream));
        assert_eq!(inflated(&stream), b"project oneproject twoproject three");
        // Over the budget, it is an error.
        assert!(read_document_stream(&stream[..], &TAGS, 20).is_err());
    }
}

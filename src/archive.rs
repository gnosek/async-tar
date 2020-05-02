use crate::entry::{Entry, EntryFields, SparseEntry, SparseReader};
use crate::error::TarError;
use crate::{other, GnuExtSparseHeader, GnuSparseHeader, Header};
use async_std::io::{self, Read, ReadExt};
use async_std::path::Path;
use async_std::sync::Arc;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct ArchiveOptions {
    ignore_zeros: bool,
    unpack_xattrs: bool,
    preserve_permissions: bool,
    preserve_mtime: bool,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            unpack_xattrs: false,
            preserve_permissions: false,
            preserve_mtime: true,
            ignore_zeros: false,
        }
    }
}

/// Configure the archive.
pub struct ArchiveBuilder<R: Read + Unpin> {
    reader: R,
    options: ArchiveOptions,
}

impl<R: Read + Unpin> ArchiveBuilder<R> {
    /// Create a new builder.
    pub fn new(reader: R) -> Self {
        ArchiveBuilder {
            reader,
            options: ArchiveOptions::default(),
        }
    }

    /// Indicate whether extended file attributes (xattrs on Unix) are preserved
    /// when unpacking this archive.
    ///
    /// This flag is disabled by default and is currently only implemented on
    /// Unix using xattr support. This may eventually be implemented for
    /// Windows, however, if other archive implementations are found which do
    /// this as well.
    pub fn set_unpack_xattrs(mut self, unpack_xattrs: bool) -> Self {
        self.options.unpack_xattrs = unpack_xattrs;
        self
    }

    /// Indicate whether extended permissions (like suid on Unix) are preserved
    /// when unpacking this entry.
    ///
    /// This flag is disabled by default and is currently only implemented on
    /// Unix.
    pub fn set_preserve_permissions(mut self, preserve: bool) -> Self {
        self.options.preserve_permissions = preserve;
        self
    }

    /// Indicate whether access time information is preserved when unpacking
    /// this entry.
    ///
    /// This flag is enabled by default.
    pub fn set_preserve_mtime(mut self, preserve: bool) -> Self {
        self.options.preserve_mtime = preserve;
        self
    }

    /// Ignore zeroed headers, which would otherwise indicate to the archive that it has no more
    /// entries.
    ///
    /// This can be used in case multiple tar archives have been concatenated together.
    pub fn set_ignore_zeros(mut self, ignore_zeros: bool) -> Self {
        self.options.ignore_zeros = ignore_zeros;
        self
    }

    /// Construct the archive, ready to accept inputs.
    pub fn build(self) -> Archive<R> {
        let Self { options, reader } = self;

        Archive {
            options,
            reader,
            pos: Arc::new(AtomicU64::new(0)),
            next: 0,
        }
    }
}

/// A top-level representation of an archive file.
///
/// This archive can have an entry added to it and it can be iterated over.
pub struct Archive<R: Read + Unpin> {
    reader: R,
    options: ArchiveOptions,
    pos: Arc<AtomicU64>,
    next: u64,
}

async fn try_read_exact<R: Read + Unpin>(
    mut reader: R,
    out_buf: &mut [u8],
) -> Option<io::Result<()>> {
    let nread = match reader.read(out_buf).await {
        Ok(0) => return None,
        Ok(nread) if nread == out_buf.len() => return Some(Ok(())),
        Ok(nread) => nread,
        Err(e) => return Some(Err(e)),
    };

    Some(reader.read_exact(&mut out_buf[nread..]).await)
}

async fn skip<R: Read + Unpin>(mut reader: R, mut amt: u64) -> io::Result<()> {
    let mut buf = [0u8; 4096 * 8];
    while amt > 0 {
        let n = std::cmp::min(amt, buf.len() as u64);
        reader.read_exact(&mut buf[..n as usize]).await?;
        amt -= n as usize as u64;
    }

    Ok(())
}

impl<R: Read + Unpin> Archive<R> {
    /// Create a new archive iterator from a reader
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            options: ArchiveOptions::default(),
            pos: Arc::new(AtomicU64::new(0)),
            next: 0,
        }
    }

    /// Create a new archive iterator from a reader
    pub fn new_with_pos(reader: R, pos: u64) -> Self {
        Self {
            reader,
            options: ArchiveOptions::default(),
            pos: Arc::new(AtomicU64::new(pos)),
            next: pos,
        }
    }

    async fn next_raw_entry_impl(
        &mut self,
    ) -> Option<io::Result<(EntryFields, SparseReader<&mut R>)>> {
        let mut header = Header::new_old();
        let mut header_pos;

        loop {
            header_pos = self.next;
            if let Err(e) = skip(
                &mut self.reader,
                self.next - self.pos.load(Ordering::Relaxed),
            )
            .await
            {
                return Some(Err(e));
            }
            self.pos.store(self.next, Ordering::Relaxed);

            match try_read_exact(&mut self.reader, header.as_mut_bytes()).await {
                None => return None,
                Some(Err(e)) => return Some(Err(e)),
                Some(Ok(())) => (),
            }
            self.pos.fetch_add(512, Ordering::Relaxed);
            self.next += 512;

            if !header.as_bytes().iter().all(|i| *i == 0) {
                break;
            }

            if !self.options.ignore_zeros {
                return None;
            }
        }

        // Make sure the checksum is ok
        let sum = header.as_bytes()[..148]
            .iter()
            .chain(&header.as_bytes()[156..])
            .fold(0, |a, b| a + (*b as u32))
            + 8 * 32;
        let cksum = match header.cksum() {
            Ok(cksum) => cksum,
            Err(e) => return Some(Err(e)),
        };
        if sum != cksum {
            return Some(Err(other("archive header checksum mismatch")));
        }

        let file_pos = self.next;
        let size = match header.entry_size() {
            Ok(size) => size,
            Err(e) => return Some(Err(e)),
        };

        let data =
            SparseReader::new_single_chunk(&mut self.reader, self.pos.clone(), size as usize);

        let ret = EntryFields {
            size,
            header_pos,
            file_pos,
            header,
            long_pathname: None,
            long_linkname: None,
            pax_extensions: None,
            unpack_xattrs: self.options.unpack_xattrs,
            preserve_permissions: self.options.preserve_permissions,
            preserve_mtime: self.options.preserve_mtime,
        };

        // Store where the next entry is, rounding up by 512 bytes (the size of
        // a header);
        let size = (size + 511) & !(512 - 1);
        self.next += size;

        Some(Ok((ret, data)))
    }

    async fn read_parse_sparse_header(
        &mut self,
        entry: &mut EntryFields,
    ) -> io::Result<SparseReader<&mut R>> {
        if !entry.header.entry_type().is_gnu_sparse() {
            return Ok(SparseReader::new_single_chunk(
                &mut self.reader,
                self.pos.clone(),
                entry.header.entry_size()? as usize,
            ));
        }

        let gnu = match entry.header.as_gnu() {
            Some(gnu) => gnu,
            None => return Err(other("sparse entry type listed but not GNU header")),
        };

        // Sparse files are represented internally as a list of blocks that are
        // read. Blocks are either a bunch of 0's or they're data from the
        // underlying archive.
        //
        // Blocks of a sparse file are described by the `GnuSparseHeader`
        // structure, some of which are contained in `GnuHeader` but some of
        // which may also be contained after the first header in further
        // headers.
        //
        // We read off all the blocks here and use the `add_block` function to
        // incrementally add them to the list of I/O block (in `entry.data`).
        // The `add_block` function also validates that each chunk comes after
        // the previous, we don't overrun the end of the file, and each block is
        // aligned to a 512-byte boundary in the archive itself.
        //
        // At the end we verify that the sparse file size (`Header::size`) is
        // the same as the current offset (described by the list of blocks) as
        // well as the amount of data read equals the size of the entry
        // (`Header::entry_size`).
        let mut chunks = VecDeque::new();

        let mut cur = 0;
        let mut remaining = entry.size;
        {
            let size = entry.size;
            let mut add_block = |block: &GnuSparseHeader| -> io::Result<_> {
                if block.is_empty() {
                    return Ok(());
                }
                let off = block.offset()?;
                let len = block.length()?;

                if (size - remaining) % 512 != 0 {
                    return Err(other(
                        "previous block in sparse file was not \
                         aligned to 512-byte boundary",
                    ));
                } else if off < cur {
                    return Err(other(
                        "out of order or overlapping sparse \
                         blocks",
                    ));
                } else if cur < off {
                    chunks.push_back(SparseEntry::Padding((off - cur) as usize));
                }
                cur = off
                    .checked_add(len)
                    .ok_or_else(|| other("more bytes listed in sparse file than u64 can hold"))?;
                remaining = remaining.checked_sub(len).ok_or_else(|| {
                    other("sparse file consumed more data than the header listed")
                })?;
                chunks.push_back(SparseEntry::Data(len as usize));
                Ok(())
            };
            for block in gnu.sparse.iter() {
                add_block(block)?
            }
            if gnu.is_extended() {
                let mut ext = GnuExtSparseHeader::new();
                ext.isextended[0] = 1;
                while ext.is_extended() {
                    match try_read_exact(&mut self.reader, ext.as_mut_bytes()).await {
                        Some(Ok(())) => (),
                        None => return Err(other("failed to read extension")),
                        Some(Err(e)) => return Err(e),
                    }

                    self.pos.fetch_add(512, Ordering::Relaxed);
                    self.next += 512;
                    for block in ext.sparse.iter() {
                        add_block(block)?;
                    }
                }
            }
        }
        if cur != gnu.real_size()? {
            return Err(other("mismatch in sparse file chunks and size in header"));
        }
        entry.size = cur;
        if remaining > 0 {
            return Err(other(
                "mismatch in sparse file chunks and entry size in header",
            ));
        }

        Ok(SparseReader::new(
            &mut self.reader,
            self.pos.clone(),
            chunks,
        ))
    }

    /// Return the next raw entry from the archive
    ///
    /// Note: do *not* mix this method with next_entry()
    pub async fn next_raw_entry(&mut self) -> Option<io::Result<Entry<&mut R>>> {
        match self.next_raw_entry_impl().await {
            None => None,
            Some(Err(e)) => Some(Err(e)),
            Some(Ok((fields, reader))) => Some(Ok(Entry {
                fields,
                data: reader,
            })),
        }
    }

    /// Return the next entry from the archive
    ///
    /// Note: do *not* mix this method with next_raw_entry()
    pub async fn next_entry(&mut self) -> Option<io::Result<Entry<&mut R>>> {
        let mut gnu_longname: Option<Vec<u8>> = None;
        let mut gnu_longlink: Option<Vec<u8>> = None;
        let mut pax_extensions: Option<Vec<u8>> = None;

        loop {
            let (mut entry, mut reader) = match self.next_raw_entry_impl().await {
                None => return None,
                Some(Err(e)) => return Some(Err(e)),
                Some(Ok(entry)) => entry,
            };

            if entry.header.as_gnu().is_some() && entry.header.entry_type().is_gnu_longname() {
                if gnu_longname.is_some() {
                    return Some(Err(other(
                        "two long name entries describing \
                         the same member",
                    )));
                }

                gnu_longname = match reader.read_all().await {
                    Ok(name) => Some(name),
                    Err(e) => return Some(Err(e)),
                };
                continue;
            }

            if entry.header.as_gnu().is_some() && entry.header.entry_type().is_gnu_longlink() {
                if gnu_longlink.is_some() {
                    return Some(Err(other(
                        "two long name entries describing \
                         the same member",
                    )));
                }
                gnu_longlink = match reader.read_all().await {
                    Ok(name) => Some(name),
                    Err(e) => return Some(Err(e)),
                };
                continue;
            }

            if entry.header.as_ustar().is_some()
                && entry.header.entry_type().is_pax_local_extensions()
            {
                if pax_extensions.is_some() {
                    return Some(Err(other(
                        "two pax extensions entries describing \
                         the same member",
                    )));
                }
                pax_extensions = match reader.read_all().await {
                    Ok(name) => Some(name),
                    Err(e) => return Some(Err(e)),
                };
                continue;
            }

            entry.long_pathname = gnu_longname.take();
            entry.long_linkname = gnu_longlink.take();
            entry.pax_extensions = pax_extensions.take();

            return match self.read_parse_sparse_header(&mut entry).await {
                Ok(reader) => Some(Ok(Entry {
                    fields: entry,
                    data: reader,
                })),
                Err(e) => Some(Err(e)),
            };
        }
    }

    /// Unpacks the contents tarball into the specified `dst`.
    ///
    /// This function will iterate over the entire contents of this tarball,
    /// extracting each file in turn to the location specified by the entry's
    /// path name.
    ///
    /// This operation is relatively sensitive in that it will not write files
    /// outside of the path specified by `dst`. Files in the archive which have
    /// a '..' in their path are skipped during the unpacking process.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> { async_std::task::block_on(async {
    /// #
    /// use async_std::fs::File;
    /// use async_tar::Archive;
    ///
    /// let mut ar = Archive::new(File::open("foo.tar").await?);
    /// ar.unpack("foo").await?;
    /// #
    /// # Ok(()) }) }
    /// ```
    pub async fn unpack<P: AsRef<Path>>(&mut self, dst: P) -> io::Result<()> {
        while let Some(entry) = self.next_entry().await {
            let mut file = entry.map_err(|e| TarError::new("failed to iterate over archive", e))?;
            file.unpack_in(dst.as_ref()).await?;
        }
        Ok(())
    }

    /// Retrieve the underlying reader
    pub fn into_inner(self) -> R {
        self.reader
    }
}

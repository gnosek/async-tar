//! An example of listing the file names of entries in an archive.
//!
//! Takes a tarball on stdin and prints out all of the entries inside.

extern crate async_tar;

use async_std::io::stdin;

use async_tar::Archive;

fn main() {
    async_std::task::block_on(async {
        let mut ar = Archive::new(stdin());
        while let Some(file) = ar.next_entry().await {
            let f = file.unwrap();
            println!("{}", f.path().unwrap().display());
        }
    });
}

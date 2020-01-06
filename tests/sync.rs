use async_tar::Archive;
use async_std::io::Cursor;

macro_rules! tar {
    ($e:expr) => {
        &include_bytes!(concat!("archives/", $e))[..]
    };
}

#[async_std::test]
async fn archive_is_sync() {
    let ar = Archive::new(Cursor::new(tar!("simple.tar")));
    let _: &dyn Send = &ar;
}

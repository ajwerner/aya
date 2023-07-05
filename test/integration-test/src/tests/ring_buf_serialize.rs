use std::os::fd::AsRawFd as _;

use aya::{maps::RingBuf, Pod};

use aya::{include_bytes_aligned, programs::UProbe, Bpf};
use tokio::{io::unix::AsyncFd, time::sleep};

use super::tokio_integration_test;

const N: usize = 10;

#[tokio_integration_test]
async fn ring_buf_async() {
    let bytes = include_bytes_aligned!(
        "../../../../target/bpfel-unknown-none/release/ring_buf_serialize.bpf.o"
    );
    let mut bpf = Bpf::load(bytes).unwrap();
    let ring_buf = bpf.take_map("RESULTS").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("test_ring_buf_serialize")
        .unwrap()
        .try_into()
        .unwrap();
    match prog.load() {
        Ok(_) => {}
        Err(e) => {
            println!("{}", e);
            panic!("failed")
        }
    }
    prog.attach(Some("do_thing"), 0, "/proc/self/exe", None)
        .unwrap();

    // Generate some random data.
    let write_handle = tokio::task::spawn(call_trigger());

    // Construct an AsyncFd from the RingBuf in order to receive readiness notifications.
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd()).unwrap();
    let mut seen = 0;
    while seen < N {
        // Wait for readiness, then clear the bit before reading so that no notifications
        // are missed.
        async_fd.readable().await.unwrap().clear_ready();
        while let Some(data) = ring_buf.next() {
            let data = &*data;
            println!("data: {:x?}", data);

            let mut offset: usize = 0;
            let foo = unsafe { &*(data.as_ptr() as *const Foo) };
            offset += core::mem::size_of::<Foo>();
            let str = unsafe {
                std::string::String::from_raw_parts(
                    data[offset..].as_ptr() as *mut _,
                    foo.str.len as usize,
                    foo.str.len as usize,
                )
            };
            offset += str.len();
            let bar = unsafe { &*(data[offset..].as_ptr() as *const Bar) };
            println!("foo: {:?}, str: {}, bar: {:?}", foo, &str, bar);
            seen += 1;
        }
    }

    // Ensure that the data that was read matches what was passed.
    write_handle.await.unwrap();
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Foo {
    a: u64,
    b: u64,
    str: Str,
    foo: *mut Foo,
    bar: *mut Bar,
}

#[derive(Debug, Clone, Copy)]
pub struct Str {
    len: u64,
    data: *mut u8,
}

unsafe impl Pod for Foo {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Bar {
    c: u64,
    d: u64,
}

static STRING: &str = "hello world";

impl Foo {
    fn new(a: u64, b: u64, c: u64, d: u64) -> *mut Foo {
        let bar = std::boxed::Box::new(Bar { c, d });
        let bar = std::boxed::Box::into_raw(bar);
        let str = Str {
            len: STRING.len() as u64,
            data: STRING.as_ptr() as *mut u8,
        };
        let foo = if d > 0 {
            Foo::new(a, b, c, d.checked_sub(1).unwrap_or_default())
        } else {
            std::ptr::null_mut()
        };
        std::boxed::Box::into_raw(std::boxed::Box::new(Foo {
            a,
            b,
            str,
            foo,
            bar,
        }))
    }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn do_thing(_foo: *mut Foo) {}

async fn call_trigger() {
    for _ in 0..N {
        sleep(std::time::Duration::from_secs(1)).await;
        do_thing(Foo::new(1, 2, 3, 16))
    }
}

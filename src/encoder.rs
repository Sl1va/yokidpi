use std::cell::RefCell;
use std::rc::Rc;

use rand::Rng;

pub trait Encoder {
    fn encode(&self, buf: Vec<u8>) -> Vec<u8>;
    fn decode(&self, buf: Vec<u8>) -> Vec<u8> {
        // by default assume that the operations are symmetric
        self.encode(buf)
    }
}

pub struct Decoder {
    encoder: Rc<Box<dyn Encoder>>,
}

impl Decoder {
    pub fn new(encoder: Rc<Box<dyn Encoder>>) -> Self {
        Decoder { encoder }
    }
}

impl Encoder for Decoder {
    fn encode(&self, buf: Vec<u8>) -> Vec<u8> {
        self.encoder.decode(buf)
    }
}

pub struct ByteReverser {}

impl Encoder for ByteReverser {
    fn encode(&self, mut buf: Vec<u8>) -> Vec<u8> {
        let len = buf.len();
        for i in 0..len / 2 {
            buf.swap(i, len - 1 - i);
        }

        // Do not require additional buffer
        buf
    }
}

#[test]
fn test_byte_reverser_encode_even() {
    let byte_reverser = ByteReverser {};
    let mut buf = vec![1, 2, 3, 4];

    buf = byte_reverser.encode(buf);
    assert_eq!(buf, [4, 3, 2, 1]);
}

#[test]
fn test_byte_reverser_decode_even() {
    let byte_reverser = ByteReverser {};
    let mut buf = vec![1, 2, 3, 4];

    buf = byte_reverser.encode(buf);
    buf = byte_reverser.decode(buf);

    assert_eq!(buf, [1, 2, 3, 4]);
}

#[test]
fn test_byte_reverser_encode_odd() {
    let byte_reverser = ByteReverser {};
    let mut buf = vec![1, 2, 3, 4, 5];

    buf = byte_reverser.encode(buf);
    assert_eq!(buf, [5, 4, 3, 2, 1]);
}

#[test]
fn test_byte_reverser_decode_odd() {
    let byte_reverser = ByteReverser {};
    let mut buf = vec![1, 2, 3, 4, 5];

    buf = byte_reverser.encode(buf);
    buf = byte_reverser.decode(buf);

    assert_eq!(buf, [1, 2, 3, 4, 5]);
}

pub struct SizeExtender {
    random: RefCell<rand::rngs::ThreadRng>,
    factor: f64,
}

impl SizeExtender {
    pub fn new(factor: f64) -> Self {
        if factor <= 1.0f64 {
            panic!("Factor can not be less or equal to 1.0");
        }
        let random = rand::thread_rng();
        SizeExtender {
            random: RefCell::new(random),
            factor,
        }
    }
}

impl Encoder for SizeExtender {
    fn encode(&self, buf: Vec<u8>) -> Vec<u8> {
        let newsize = ((buf.len() as f64) * self.factor).floor() as usize;
        let mut newbuf: Vec<u8> = Vec::from((buf.len() as u32).to_le_bytes());

        newbuf.extend(buf);

        while newbuf.len() < newsize as usize {
            newbuf.push(self.random.borrow_mut().gen_range(0..256) as u8);
        }

        newbuf
    }

    fn decode(&self, buf: Vec<u8>) -> Vec<u8> {
        let oldsize = u32::from_le_bytes((&buf[0..4]).try_into().unwrap());
        (&buf[4..oldsize as usize + 4]).to_vec()
    }
}

#[test]
#[should_panic]
fn test_size_extender_panic() {
    let _ = SizeExtender::new(0.8);
}

#[test]
fn test_size_extender_encode() {
    let extender = SizeExtender::new(1.8);
    let mut buf = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    buf = extender.encode(buf);
    assert_eq!(buf.len(), 18);

    assert_eq!(&buf[4..14], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
}

#[test]
fn test_size_extender_decode() {
    let extender = SizeExtender::new(1.8);
    let mut buf = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    buf = extender.encode(buf);
    buf = extender.decode(buf);
    assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
}

pub struct NeighbourBlockSwapper {
    block_size: usize,
}

impl NeighbourBlockSwapper {
    pub fn new(block_size: usize) -> Self {
        Self {block_size}
    }
}

impl Encoder for NeighbourBlockSwapper {
    fn encode(&self, mut buf: Vec<u8>) -> Vec<u8> {
        for block in (1..(buf.len() / self.block_size)).step_by(2) {
            for offset in 0..self.block_size {
                let cur = block * self.block_size;
                let prev = (block - 1) * self.block_size;
                buf.swap(cur + offset, prev + offset);
            }
        }

        buf
    }
}

#[test]
fn test_neighbor_block_swapper_encode_even() {
    let nswapper = NeighbourBlockSwapper { block_size: 3 };

    let mut buf = vec![1, 2, 3, 4, 5, 6];
    buf = nswapper.encode(buf);

    assert_eq!(buf, [4, 5, 6, 1, 2, 3]);
}

#[test]
fn test_neighbor_block_swapper_decode_even() {
    let nswapper = NeighbourBlockSwapper { block_size: 3 };

    let mut buf = vec![1, 2, 3, 4, 5, 6];
    buf = nswapper.encode(buf);
    buf = nswapper.decode(buf);

    assert_eq!(buf, [1, 2, 3, 4, 5, 6]);
}

#[test]
fn test_neighbor_block_swapper_encode_odd() {
    let nswapper = NeighbourBlockSwapper { block_size: 3 };

    let mut buf = vec![1, 2, 3, 4, 5, 6, 7, 8];
    buf = nswapper.encode(buf);

    assert_eq!(buf, [4, 5, 6, 1, 2, 3, 7, 8]);
}

#[test]
fn test_neighbor_block_swapper_decode_odd() {
    let nswapper = NeighbourBlockSwapper { block_size: 3 };

    let mut buf = vec![1, 2, 3, 4, 5, 6, 7, 8];
    buf = nswapper.encode(buf);
    buf = nswapper.decode(buf);

    assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
}

pub struct XorEncryptor {
    key: Vec<u8>,
}

impl From<Vec<u8>> for XorEncryptor {
    fn from(key: Vec<u8>) -> Self {
        XorEncryptor { key }
    }
}

impl Encoder for XorEncryptor {
    fn encode(&self, mut buf: Vec<u8>) -> Vec<u8> {
        let key_len = self.key.len();

        for i in 0..buf.len() {
            buf[i] ^= self.key[i % key_len];
        }

        buf
    }
}

#[test]
fn test_xor_encode() {
    let xor_encoder = XorEncryptor::from(vec![153, 22, 87, 44]);
    let mut buf = vec![1, 2, 3, 100, 12, 33, 0];

    buf = xor_encoder.encode(buf);

    assert_eq!(
        buf,
        [1 ^ 153, 2 ^ 22, 3 ^ 87, 100 ^ 44, 12 ^ 153, 33 ^ 22, 0 ^ 87]
    );
}

#[test]
fn test_xor_decode() {
    let xor_encoder = XorEncryptor::from(vec![153, 22, 87, 44]);
    let mut buf = vec![1, 2, 3, 100, 12, 33, 0];

    buf = xor_encoder.encode(buf);
    buf = xor_encoder.decode(buf);

    assert_eq!(buf, [1, 2, 3, 100, 12, 33, 0]);
}

pub struct EncoderChain {
    chain: Vec<Box<dyn Encoder>>,
}

impl EncoderChain {
    pub fn new() -> Self {
        Self { chain: Vec::new() }
    }

    pub fn add(&mut self, encoder: Box<dyn Encoder>) {
        self.chain.push(encoder);
    }
}

impl From<Vec<Box<dyn Encoder>>> for EncoderChain {
    fn from(value: Vec<Box<dyn Encoder>>) -> Self {
        Self { chain: value }
    }
}

impl Encoder for EncoderChain {
    fn encode(&self, buf: Vec<u8>) -> Vec<u8> {
        let mut buf: Vec<u8> = buf.to_vec();

        for encoder in &self.chain {
            // println!("{:?}", buf);
            buf = encoder.encode(buf);
        }

        buf
    }

    fn decode(&self, buf: Vec<u8>) -> Vec<u8> {
        let mut buf: Vec<u8> = buf.to_vec();

        for encoder in self.chain.iter().rev() {
            // println!("{:?}", buf);
            buf = encoder.decode(buf);
        }

        buf
    }
}

#[test]
fn test_chain_reverser_extender_swapper_xor() {
    let chain: Vec<Box<dyn Encoder>> = vec![
        Box::new(NeighbourBlockSwapper { block_size: 2 }),
        Box::new(ByteReverser {}),
        Box::new(SizeExtender::new(1.8)),
        Box::new(ByteReverser {}),
        Box::new(NeighbourBlockSwapper { block_size: 3 }),
        Box::new(ByteReverser {}),
        Box::new(XorEncryptor::from(vec![94, 29, 201, 124])),
    ];
    let chain = EncoderChain::from(chain);

    let mut buf = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    buf = chain.encode(buf);
    assert_eq!(buf.len(), 18);

    let decoded = chain.decode(buf);
    assert_eq!(decoded, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
}

mod encoder;
mod gateway;

use std::rc::Rc;

use encoder::*;
use gateway::Gateway;

fn main() {
    let encoder_chain: Vec<Box<dyn Encoder>> = vec![
        Box::new(NeighbourBlockSwapper::new(2)),
        Box::new(ByteReverser {}),
        Box::new(SizeExtender::new(1.8)),
        Box::new(ByteReverser {}),
        Box::new(NeighbourBlockSwapper::new(3)),
        Box::new(ByteReverser {}),
        Box::new(XorEncryptor::from(vec![94, 29, 201, 124])),
    ];

    let encoder: Rc<Box<dyn Encoder>> = Rc::new(Box::new(EncoderChain::from(encoder_chain)));
    let decoder: Rc<Box<dyn Encoder>> = Rc::new(Box::new(Decoder::new(encoder.clone())));

    let local_conn = Rc::new(Gateway::new(decoder.clone()));
    let remote_conn = Rc::new(Gateway::new(encoder.clone()));

    local_conn.init_async(remote_conn.clone());
    remote_conn.init_async(local_conn.clone());
}

mod encoder;
mod gateway;

use std::rc::Rc;

use encoder::*;
use gateway::Gateway;
use mio::net::UdpSocket;
use mio::{event, Events, Interest, Poll, Token};
use std::net::SocketAddr;

fn main() -> std::io::Result<()> {
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

    // let local_conn = Rc::new(Gateway::new(decoder.clone()));
    // let remote_conn = Rc::new(Gateway::new(encoder.clone()));

    // create polling instances

    // local_conn.init_async(remote_conn.clone());
    // remote_conn.init_async(local_conn.clone());

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);

    let local_addr: SocketAddr = "127.0.0.1:8383".parse().unwrap();
    let remote_addr: SocketAddr = "127.0.0.1:8585".parse().unwrap();

    let mut local_sock = UdpSocket::bind(local_addr)?;
    let mut remote_sock = UdpSocket::bind(remote_addr)?;

    let mut local_client: Option<SocketAddr> = None;
    let mut remote_client: Option<SocketAddr> = None;

    poll.registry().register(
        &mut local_sock,
        Token(0),
        Interest::READABLE.add(Interest::WRITABLE),
    )?;
    poll.registry().register(
        &mut remote_sock,
        Token(1),
        Interest::READABLE.add(Interest::WRITABLE),
    )?;

    loop {
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            match event.token() {
                Token(0) => {
                    let mut buf = [0; 1024];
                    if let Ok((n, _local_client)) = local_sock.recv_from(&mut buf) {
                        let encoded = encoder.encode(buf[0..n].to_vec());
                        local_client = Some(_local_client);

                        if let Some(conn) = remote_client {
                            match remote_sock.send_to(&encoded, conn) {
                                Ok(_) => println!(
                                    "Successfully send to remote sock ({:?})",
                                    remote_client
                                ),
                                Err(err) => println!("Failed to send to remote sock: {:?}", err),
                            }
                        }

                        println!("Received {} bytes on local socket", n);
                    }
                }

                Token(1) => {
                    let mut buf = [0; 1024];
                    if let Ok((n, _remote_client)) = remote_sock.recv_from(&mut buf) {
                        remote_client = Some(_remote_client);

                        if &buf[0..2] == b"hi" {
                            println!("Initialized remote connection");
                            continue;
                        }

                        let decoded = decoder.decode(buf[0..n].to_vec());

                        if let Some(conn) = local_client {
                            match local_sock.send_to(&decoded, conn) {
                                Ok(_) => {
                                    println!("Successfully send to local sock ({:?})", local_client)
                                }
                                Err(err) => println!("Failed to send to local sock: {:?}", err),
                            }
                        }

                        println!("Received {} bytes on remote socket", n);
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

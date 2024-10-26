mod encoder;
mod gateway;

use std::io::{empty, Error};
use std::rc::Rc;
use std::{default, env};

use encoder::*;
use mio::net::UdpSocket;
use mio::{event, Events, Interest, Poll, Token};
use std::net::SocketAddr;

fn setup_client(server_addr: SocketAddr) -> std::io::Result<UdpSocket> {
    // Initial garbage message to the server (to bypass DPI handshake detection)
    let server_sock = UdpSocket::bind("0.0.0.0:0".parse().unwrap())?;
    if let Err(err) = server_sock.connect(server_addr) {
        return Err(err);
    }

    let garbage_gen = SizeExtender::new(64.0);
    let mut payload = vec![0u8];
    payload = garbage_gen.encode(payload);

    if let Ok(n) = server_sock.send(&payload) {
        println!(
            "Successfully sent initial garbage message to {} ({} bytes)",
            server_addr, n
        );
    } else {
        return Err(Error::new(
            std::io::ErrorKind::NotConnected,
            "Failed to send initial garbage message",
        ));
    }

    Ok(server_sock)
}

fn setup_server(local_serv_addr: SocketAddr) -> std::io::Result<UdpSocket>{
    // Initial garbage message to the server (to bypass DPI handshake detection)
    let server_sock = UdpSocket::bind("0.0.0.0:0".parse().unwrap())?;
    server_sock.connect(local_serv_addr)?;

    Ok(server_sock)
}

fn main() -> std::io::Result<()> {
    let encoder_chain: Vec<Box<dyn Encoder>> = vec![
        Box::new(NeighbourBlockSwapper::new(2)),
        Box::new(ByteReverser {}),
        Box::new(SizeExtender::new(1.8)),
        Box::new(ByteReverser {}),
        Box::new(NeighbourBlockSwapper::new(3)),
        Box::new(ByteReverser {}),
        Box::new(PacketVerifier {}),
        Box::new(XorEncryptor::from(vec![94, 29, 201, 124])),
    ];

    let mut encoder: Rc<Box<dyn Encoder>> = Rc::new(Box::new(EncoderChain::from(encoder_chain)));

    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).expect("Mode must be specified");
    let addr = args.get(2).expect("Remote address must be specified");
    let addr: SocketAddr = addr
        .parse()
        .expect("Remote: Wrong address format specified");

    let local_endpoint = args.get(3).expect("Listen address must be specified");
    let local_endpoint: SocketAddr = local_endpoint
        .parse()
        .expect("Local: Wrong address format specified");

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);

    let mut local_sock = UdpSocket::bind(local_endpoint).expect("Failed to bind local sock");

    let mut remote_sock;
    match mode.as_str() {
        "client" => remote_sock = setup_client(addr).expect("Failed to initalize client socket"),
        "server" => { 
            // encoder = Rc::new(Box::new(Decoder::new(encoder)));
            remote_sock = local_sock;
            local_sock = setup_server(addr).expect("Failed to initalize client socket");
        },
        _ => panic!("Unknown runtime mode specified (available: client|server)"),
    }

    // let mut local_client: Option<SocketAddr> = None;
    // let mut remote_client: Option<SocketAddr> = None;

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
                        let encoded = encoder.decode(buf[0..n].to_vec());
                        println!("Received {} bytes on local socket", n);

                        let _ = local_sock.connect(_local_client);
                        if encoded.len() == 0 {
                            println!("Local: encoded message is empty");
                            continue;
                        }

                        match remote_sock.send(&encoded) {
                            Ok(m) => println!("Successfully send {} bytes to remote sock", m),
                            Err(err) => println!("Failed to send to remote sock: {:?}", err),
                        }
                    }
                }

                Token(1) => {
                    let mut buf = [0; 1024];
                    if let Ok((n, _remote_client)) = remote_sock.recv_from(&mut buf) {
                        let decoded = encoder.encode(buf[0..n].to_vec());
                        println!("Received {} bytes on remote socket", n);

                        let _ = remote_sock.connect(_remote_client);
                        if decoded.len() == 0 {
                            println!("Remote: decoded message is empty");
                            continue;
                        }

                        match local_sock.send(&decoded) {
                            Ok(m) => println!("Successfully send {} bytes to local sock", m),
                            Err(err) => println!("Failed to send to local sock: {:?}", err),
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

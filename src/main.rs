mod encoder;
mod gateway;

use std::time::Duration;
use std::{env, io, thread};

use encoder::*;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use std::net::SocketAddr;

fn prepare_client(
    encoded_addr: SocketAddr,
    decoded_addr: SocketAddr,
    encoder: &Box<dyn Encoder>,
) -> std::io::Result<(UdpSocket, UdpSocket)> {
    // In client mode, decoded gateway is connection to local client (listen to it).
    // Encoded gateway is connection to remote server (connect to it).

    // As a result - decoded gateway is not associated with any clients,
    // it only listens from the  fixed addres
    let decoded_gateway = UdpSocket::bind(decoded_addr)?;

    // Wait till the first client and associate decoded gateway with it
    // (Message will be dropped, but it should be OK due to UDP nature)
    let mut buf = vec![0u8; 1024];
    let local_client: SocketAddr;

    loop {
        match decoded_gateway.recv_from(&mut buf) {
            Ok((_, addr)) => {
                local_client = addr;
                break;
            }

            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Do some busy waiting on non-blocking socket
                thread::sleep(Duration::from_millis(100));
                continue;
            }

            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Failed to establish connection with local client",
                ));
            }
        }
    }

    // Finally, associate local decoder with local client
    decoded_gateway.connect(local_client)?;
    println!(
        "Successfully established connection with local client {}",
        local_client
    );

    // Meanwhile encoded gateway is explicitly associated with remote socket
    // (we can let the system to set local credentials)
    let encoded_gateway = UdpSocket::bind("0.0.0.0:0".parse().unwrap())?;
    encoded_gateway.connect(encoded_addr)?;

    // Send HELLO message to the server in order to immediatelly create association for server
    let enc_msg = encoder.encode("HELLO FROM YOKI CLIENT".as_bytes().to_vec());

    match encoded_gateway.send(&enc_msg) {
        Ok(n) => {
            println!("Successfully sent HELLO message to server ({} bytes)", n);
            Ok((encoded_gateway, decoded_gateway))
        }
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "Failed to send HELLO message",
        )),
    }
}

fn prepare_server(
    encoded_addr: SocketAddr,
    decoded_addr: SocketAddr,
    encoder: &Box<dyn Encoder>,
) -> std::io::Result<(UdpSocket, UdpSocket)> {
    // In server mode, decoded gateway is connection to local server (connect to it).
    // Encoded gateway is connection to remote client (listen to it)

    // As a result, decoded gateway is explicitly associated with local server
    let decoded_gateway = UdpSocket::bind("0.0.0.0:0".parse().unwrap())?;
    decoded_gateway.connect(decoded_addr)?;

    // Meanwhile encoded gateway just listens the specified port for incoming connections
    let encoded_gateway = UdpSocket::bind(encoded_addr)?;

    // Client will send HELLO message for immediate association
    let mut buf = vec![0u8; 1024];

    // Message is blocking, therefore use busy waiting
    let remote_addr: SocketAddr;
    loop {
        match encoded_gateway.recv_from(&mut buf) {
            Ok((n, addr)) => {
                buf = encoder.decode(buf[0..n].to_vec());
                remote_addr = addr;
                break;
            }

            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Do some busy waiting on non-blocking socket
                thread::sleep(Duration::from_millis(100));
                continue;
            }

            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Failed to receive HELLO message",
                ));
            }
        }
    }

    if buf != "HELLO FROM YOKI CLIENT".as_bytes().to_vec() {
        return Err(std::io::Error::new(
            io::ErrorKind::InvalidData,
            "HELLO message is corrupted",
        ));
    }

    // Finally, associate encoded gateway with remote client
    encoded_gateway.connect(remote_addr)?;
    println!(
        "Successfuly associated encoded gateway with {}",
        remote_addr
    );

    Ok((encoded_gateway, decoded_gateway))
}

fn main() -> std::io::Result<()> {
    let encoder_chain: Vec<Box<dyn Encoder>> = vec![
        Box::new(NeighbourBlockSwapper::new(2)),
        Box::new(ByteReverser {}),
        Box::new(SizeExtender::new(1.1)),
        Box::new(ByteReverser {}),
        Box::new(NeighbourBlockSwapper::new(3)),
        Box::new(ByteReverser {}),
        Box::new(PacketVerifier {}),
        Box::new(XorEncryptor::from(vec![94, 29, 201, 124])),
    ];

    let encoder: Box<dyn Encoder> = Box::new(EncoderChain::from(encoder_chain));

    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).expect("Mode must be specified");

    // Encoded gateway - accepts **encoded** traffic for further processing
    let encoded_gateway_addr = args.get(2).expect("Encoded gateway must be specified");

    // Decoded gateway - accept **not encoded** traffic for futher processing
    let decoded_gateway_addr = args.get(3).expect("Decoded gateway must be specified");

    // Transform gateways into socket addresses
    let encoded_gateway_addr: SocketAddr = encoded_gateway_addr
        .parse()
        .expect("Wrong format for encoded gateway");
    let decoded_gateway_addr: SocketAddr = decoded_gateway_addr
        .parse()
        .expect("Wrong format for decoded gateway");

    let mut encoded_gateway: UdpSocket;
    let mut decoded_gateway: UdpSocket;

    match mode.as_str() {
        "client" => {
            (encoded_gateway, decoded_gateway) =
                prepare_client(encoded_gateway_addr, decoded_gateway_addr, &encoder)
                    .expect("Failed to initialize client");
        }

        "server" => {
            (encoded_gateway, decoded_gateway) =
                prepare_server(encoded_gateway_addr, decoded_gateway_addr, &encoder)
                    .expect("Failed to initialize server");
        }

        _ => {
            panic!("Mode \"{}\" not supported", mode);
        }
    }

    // Register polling events
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);

    poll.registry()
        .register(&mut decoded_gateway, Token(0), Interest::READABLE)?;
    poll.registry()
        .register(&mut encoded_gateway, Token(1), Interest::READABLE)?;

    let mut encoded_counter = 0u32;
    let mut decoded_counter = 0u32;

    loop {
        poll.poll(&mut events, None)?;

        let mut buf = vec![0u8; 1024];
        for event in events.iter() {
            match event.token() {
                Token(0) => {
                    // Raw (decoded) traffic comes here

                    if let Ok((n, addr)) = decoded_gateway.recv_from(&mut buf) {
                        // Encode data and send to encoder client
                        decoded_counter += 1;
                        println!("[{}] Received decoded message from {} ({} bytes)", decoded_counter, addr, n);
                        buf = encoder.encode(buf[0..n].to_vec());

                        // do not transfer empty messages
                        if buf.len() == 0 {
                            continue;
                        }

                        thread::sleep(Duration::from_millis(100));
                        match encoded_gateway.send(&buf) {
                            Ok(m) => {
                                println!(
                                    "Sent encoded message to {} ({} bytes)",
                                    encoded_gateway.peer_addr().unwrap(),
                                    m
                                );
                            }

                            Err(err) => {
                                println!(
                                    "Failed to send encoded message to {} ({})",
                                    encoded_gateway.peer_addr().unwrap(),
                                    err
                                );
                            }
                        }
                    }
                }

                Token(1) => {
                    // Encoded traffic comes here

                    if let Ok((n, addr)) = encoded_gateway.recv_from(&mut buf) {
                        // Decode data and send to decoder client
                        encoded_counter += 1;
                        println!("[{}] Received encoded message from {} ({} bytes)", encoded_counter, addr, n);
                        buf = encoder.decode(buf[0..n].to_vec());

                        // do not transfer empty messages
                        if buf.len() == 0 {
                            continue;
                        }

                        match decoded_gateway.send(&buf) {
                            Ok(m) => {
                                println!(
                                    "Sent decoded message to {} ({} bytes)",
                                    decoded_gateway.peer_addr().unwrap(),
                                    m
                                );
                            }

                            Err(err) => {
                                println!(
                                    "Failed to send encoded message to {} ({})",
                                    decoded_gateway.peer_addr().unwrap(),
                                    err
                                );
                            }
                        }
                    }
                }

                _ => unreachable!(),
            }
        }
    }
}

use std::{io::Write, rc::Rc};
use crate::Encoder;

pub struct Gateway {
    encoder: Rc<Box<dyn Encoder>>,
}

impl Gateway {
    pub fn new(encoder: Rc<Box<dyn Encoder>>) -> Self {
        Self {encoder}
    }

    pub fn init_async(&self, endpoint: Rc<dyn Write>) {
        
    }
}

impl Write for Gateway {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut buf = buf.to_vec();
        buf = self.encoder.encode(buf);

        // TODO: Write to socket event?
        
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
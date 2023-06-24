use std::io::{Result, Write, Read};
use salsa20;
use rsa;
use rand::rngs::OsRng;
use rsa::pkcs1::{EncodeRsaPublicKey, DecodeRsaPublicKey};
use salsa20::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;

pub trait Stream: Read + Write + Clone {}
impl<T: Read + Write + Clone> Stream for T {}

pub struct ASecure<T: Stream> {
    pub stream: T,
    pub key_mine: Vec<u8>,
    pub key_other: Vec<u8>,
    pub rsa_mine: rsa::RsaPrivateKey,
    pub rsa_other: rsa::RsaPublicKey
}
impl<T: Stream> ASecure<T> {
    pub fn new(is_conn_starter: bool, stream: &mut T) -> Result<Self> {
        let key_rsa_mine: rsa::RsaPrivateKey;
        let key_rsa_other: rsa::RsaPublicKey;
        let key_cam_mine: Vec<u8>;
        let key_cam_other: Vec<u8>;
        if is_conn_starter {
            key_rsa_mine = rsa::RsaPrivateKey::new(&mut OsRng, 4096).unwrap();
            stream.write_all(key_rsa_mine.to_public_key().to_pkcs1_der().unwrap().as_bytes())?;
            stream.flush()?;
            let mut temp: Vec<u8> = vec![];
            stream.read_to_end(&mut temp)?;
            key_rsa_other = rsa::RsaPublicKey::from_pkcs1_der(&temp).unwrap();
            let mut dest = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut dest);
            key_cam_mine = dest.to_vec();
            stream.write_all(key_rsa_other.encrypt(&mut OsRng, rsa::Pkcs1v15Encrypt, key_cam_mine.as_slice()).unwrap().as_slice())?;
            stream.flush()?;
            let mut temp2: Vec<u8> = vec![];
            stream.read_to_end(&mut temp2)?;
            key_cam_other = key_rsa_mine.decrypt(rsa::Pkcs1v15Encrypt, temp2.as_slice()).unwrap();
        } else {
            key_rsa_mine = rsa::RsaPrivateKey::new(&mut OsRng, 4096).unwrap();
            let mut temp: Vec<u8> = vec![];
            stream.read_to_end(&mut temp)?;
            key_rsa_other = rsa::RsaPublicKey::from_pkcs1_der(&temp).unwrap();
            stream.write_all(key_rsa_mine.to_public_key().to_pkcs1_der().unwrap().as_bytes())?;
            stream.flush()?;
            let mut dest = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut dest);
            key_cam_mine = dest.to_vec();
            let mut temp2: Vec<u8> = vec![];
            stream.read_to_end(&mut temp2)?;
            key_cam_other = key_rsa_mine.decrypt(rsa::Pkcs1v15Encrypt, temp2.as_slice()).unwrap();
            stream.write_all(key_rsa_other.encrypt(&mut OsRng, rsa::Pkcs1v15Encrypt, key_cam_mine.as_slice()).unwrap().as_slice())?;
            stream.flush()?;
        }
        Ok(Self {stream: stream.clone(), key_mine: key_cam_mine, key_other: key_cam_other, rsa_mine: key_rsa_mine, rsa_other: key_rsa_other})
    }
}
impl<T: Stream> Read for ASecure<T> {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize> {
        let mut temp: Vec<u8> = Vec::new();
        self.stream.read_to_end(&mut temp).unwrap();
        let nonce = self.rsa_mine.decrypt(rsa::Pkcs1v15Encrypt, temp[0..512].as_ref()).unwrap();
        let mut cipher = salsa20::Salsa20::new(salsa20::Key::from_slice(&self.key_mine.as_slice()), salsa20::Nonce::from_slice(&nonce.as_slice()));
        let mut message = temp[512..temp.len()].to_vec();
        cipher.apply_keystream(&mut message);
        buf.write(message.as_slice())
    }
}
impl<T: Stream> Write for ASecure<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut encnonce = self.rsa_other.encrypt(&mut OsRng, rsa::Pkcs1v15Encrypt, &nonce).unwrap();
        let mut encmsg = buf.clone().to_vec();
        let mut cipher = salsa20::Salsa20::new(salsa20::Key::from_slice(&self.key_other.as_slice()), salsa20::Nonce::from_slice(&nonce.as_slice()));
        cipher.apply_keystream(&mut encmsg);
        let mut tosend: Vec<u8> = Vec::new();
        tosend.append(&mut encnonce);
        tosend.append(&mut encmsg);
        self.stream.write(&tosend)
    }
    fn flush(&mut self) -> Result<()> {
        self.stream.flush()
    }
}
impl<T: Stream> Clone for ASecure<T> {
    fn clone(&self) -> Self {
        Self {stream: self.stream.clone(), key_mine: self.key_mine.clone(), key_other: self.key_other.clone(), rsa_mine: self.rsa_mine.clone(), rsa_other: self.rsa_other.clone()}
    }
}

pub struct LittleEndian<T: Stream> {
    pub stream: T
}
impl<T: Stream> LittleEndian<T> {
    pub fn new(stream: &mut T) -> Result<Self> {
        Ok(Self {stream: stream.clone()})
    }
}
impl<T: Stream> Read for LittleEndian<T> {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize> {
        let mut temp: Vec<u8> = Vec::new();
        self.stream.read_to_end(&mut temp)?;
        buf.write(&temp[4..temp.len()])
    }
}
impl<T: Stream> Write for LittleEndian<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut tosend: Vec<u8> = Vec::new();
        let len = buf.len() as u32;
        let mut buf2 = buf.clone().to_vec();
        tosend.append(&mut len.to_le_bytes().to_vec());
        tosend.append(&mut buf2);
        self.stream.write(&tosend)
    }
    fn flush(&mut self) -> Result<()> {
        self.stream.flush()
    }
}
impl<T: Stream> Clone for LittleEndian<T> {
    fn clone(&self) -> Self {
        Self {stream: self.stream.clone()}
    }
}

pub struct BigEndian<T: Stream> {
    pub stream: T
}
impl<T: Stream> BigEndian<T> {
    pub fn new(stream: &mut T) -> Result<Self> {
        Ok(Self {stream: stream.clone()})
    }
}
impl<T: Stream> Read for BigEndian<T> {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize> {
        let mut temp: Vec<u8> = Vec::new();
        self.stream.read_to_end(&mut temp)?;
        buf.write(&temp[4..temp.len()])
    }
}
impl<T: Stream> Write for BigEndian<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut tosend: Vec<u8> = Vec::new();
        let len = buf.len() as u32;
        let mut buf2 = buf.clone().to_vec();
        tosend.append(&mut len.to_be_bytes().to_vec());
        tosend.append(&mut buf2);
        self.stream.write(&tosend)
    }
    fn flush(&mut self) -> Result<()> {
        self.stream.flush()
    }
}
impl<T: Stream> Clone for BigEndian<T> {
    fn clone(&self) -> Self {
        Self {stream: self.stream.clone()}
    }
}

pub mod tcp {
    use std::net::TcpStream;
    use std::io::{Result, Write, Read};

    pub struct Stream {
        pub stream: TcpStream
    }
    impl Stream {
        pub fn new(stream: &mut TcpStream) -> Result<Self> {
            Ok(Self {stream: stream.try_clone()?})
        }
    }
    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.stream.read_to_end(&mut buf.to_vec())
        }
    }
    impl Write for Stream {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.stream.write(buf)
        }
        fn flush(&mut self) -> Result<()> {
            self.stream.flush()
        }
    }
    impl Clone for Stream {
        fn clone(&self) -> Self {
            Self {stream: self.stream.try_clone().unwrap()}
        }
    }
}
pub mod utils {
    pub fn u8_to_bool_array(value: u8) -> [bool; 8] {
        let mut result = [false; 8];
        for i in 0..8 {
            result[i] = ((value >> i) & 1) != 0;
        }
        result
    }
    pub fn bool_array_to_u8(array: [bool; 8]) -> u8 {
        let mut result = 0;
        for i in 0..8 {
            if array[i] {
                result |= 1 << i;
            }
        }
        result
    }
    pub fn vec_u8_to_vec_bool_array(vec: Vec<u8>) -> Vec<[bool; 8]> {
        vec.into_iter().map(u8_to_bool_array).collect()
    }
    pub fn vec_bool_array_to_vec_u8(vec: Vec<[bool; 8]>) -> Vec<u8> {
        vec.into_iter().map(bool_array_to_u8).collect()
    }
    pub fn vec_bool_array_to_vec_bool(vec: Vec<[bool; 8]>) -> Vec<bool> {
        vec.into_iter().flatten().collect()
    }
    pub fn vec_bool_to_vec_bool_array(vec: Vec<bool>) -> Vec<[bool; 8]> {
        vec.chunks(8).map(|chunk| {
            let mut array = [false; 8];
            for (i, &value) in chunk.iter().enumerate() {
                array[i] = value;
            }
            array
        }).collect()
    }    
}
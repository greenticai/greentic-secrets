use rand::Rng;

pub fn random_bytes(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    rand::rng().fill_bytes(&mut buf);
    buf
}

pub fn small_payload() -> Vec<u8> {
    random_bytes(16)
}

pub fn medium_payload() -> Vec<u8> {
    random_bytes(1024)
}

//! Known-answer tests: the original ChaCha vectors from the eSTREAM reference
//! implementation used by Bouncy Castle's `ChaChaTest`, RFC 8439, and the
//! XChaCha draft. Each vector runs through every engine that supports it.

mod common;

use common::{Engine, keystream, unhex};
use tc_chacha::{
    ChaCha7539Engine, ChaCha7539PortableEngine, ChaChaEngine, ChaChaPortableEngine,
    XChaCha20Engine, XChaCha20PortableEngine,
};

/// Checks `expected` against the keystream bytes starting at `offset`.
fn check_at<E: Engine>(engine: E, key: &[u8], iv: &[u8], vectors: &[(usize, &str)]) {
    let length = vectors
        .iter()
        .map(|(offset, hex)| offset + unhex(hex).len())
        .max()
        .unwrap();
    let stream = keystream(engine, key, iv, length);
    for (offset, hex) in vectors {
        let expected = unhex(hex);
        assert_eq!(
            &stream[*offset..offset + expected.len()],
            expected,
            "{offset}"
        );
    }
}

/// XORs `plaintext` with the keystream from block one, as the RFC 8439 and
/// XChaCha examples do (block zero is reserved for the Poly1305 key).
fn encrypt_from_block_one<E: Engine>(
    engine: E,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let stream = keystream(engine, key, iv, 64 + plaintext.len());
    stream[64..]
        .iter()
        .zip(plaintext)
        .map(|(k, p)| k ^ p)
        .collect()
}

fn check_chacha20_128_bit_key_vector<E: Engine>(engine: E) {
    let key = unhex("80000000000000000000000000000000");
    check_at(
        engine,
        &key,
        &[0; 8],
        &[
            (
                0,
                "FBB87FBB8395E05DAA3B1D683C422046 F913985C2AD9B23CFC06C1D8D04FF213
                 D44A7A7CDB84929F915420A8A3DC58BF 0F7ECB4B1F167BB1A5E6153FDAF4493D",
            ),
            (
                192,
                "D9485D55B8B82D792ED1EEA8E93E9BC1 E2834AD0D9B11F3477F6E106A2F6A5F2
                 EA8244D5B925B8050EAB038F58D4DF57 7FAFD1B89359DAE508B2B10CBD6B488E",
            ),
            (
                256,
                "08661A35D6F02D3D9ACA8087F421F7C8 A42579047D6955D937925BA21396DDD4
                 74B1FC4ACCDCAA33025B4BCE817A4FBF 3E5D07D151D7E6FE04934ED466BA4779",
            ),
            (
                448,
                "A7E16DD38BA48CCB130E5BE9740CE359 D631E91600F85C8A5D0785A612D1D987
                 90780ACDDC26B69AB106CCF6D866411D 10637483DBF08CC5591FD8B3C87A3AE0",
            ),
        ],
    );
}

#[test]
fn chacha20_with_a_128_bit_key_matches_bouncy_castle_at_four_offsets() {
    check_chacha20_128_bit_key_vector(ChaChaPortableEngine::new());
    check_chacha20_128_bit_key_vector(ChaChaEngine::new());
}

fn check_chacha12_vector<E: Engine>(engine: E) {
    check_at(
        engine,
        &unhex("80000000000000000000000000000000"),
        &[0; 8],
        &[(
            0,
            "36CF0D56E9F7FBF287BC5460D95FBA94 AA6CBF17D74E7C784DDCF7E0E882DDAE
             3B5A58243EF32B79A04575A8E2C2B73D C64A52AA15B9F88305A8F0CA0B5A1A25",
        )],
    );
}

fn check_chacha8_vector<E: Engine>(engine: E) {
    check_at(
        engine,
        &unhex("80000000000000000000000000000000"),
        &[0; 8],
        &[(
            0,
            "BEB1E81E0F747E43EE51922B3E87FB38 D0163907B4ED49336032AB78B67C2457
             9FE28F751BD3703E51D876C017FAA435 89E63593E03355A7D57B2366F30047C5",
        )],
    );
}

#[test]
fn reduced_round_chacha12_and_chacha8_match_bouncy_castle() {
    check_chacha12_vector(ChaChaPortableEngine::with_rounds(12).unwrap());
    check_chacha12_vector(ChaChaEngine::with_rounds(12).unwrap());
    check_chacha8_vector(ChaChaPortableEngine::with_rounds(8).unwrap());
    check_chacha8_vector(ChaChaEngine::with_rounds(8).unwrap());
}

fn check_chacha20_256_bit_key_vector<E: Engine>(engine: E) {
    let key = unhex("0053A6F94C9FF24598EB3E91E4378ADD 3083D6297CCF2275C81B6EC11467BA0D");
    let iv = unhex("0D74DB42A91077DE");
    check_at(
        engine,
        &key,
        &iv,
        &[
            (
                0,
                "57459975BC46799394788DE80B928387 862985A269B9E8E77801DE9D874B3F51
                 AC4610B9F9BEE8CF8CACD8B5AD0BF17D 3DDF23FD7424887EB3F81405BD498CC3",
            ),
            (
                65_472,
                "EF9AEC58ACE7DB427DF012B2B91A0C1E 8E4759DCE9CDB00A2BD59207357BA06C
                 E02D327C7719E83D6348A6104B081DB0 3908E5186986AE41E3AE95298BB7B713",
            ),
            (
                65_536,
                "17EF5FF454D85ABBBA280F3A94F1D26E 950C7D5B05C4BB3A78326E0DC5731F83
                 84205C32DB867D1B476CE121A0D7074B AA7EE90525D15300F48EC0A6624BD0AF",
            ),
        ],
    );
}

#[test]
fn chacha20_with_a_256_bit_key_matches_bouncy_castle_past_64_kib() {
    check_chacha20_256_bit_key_vector(ChaChaPortableEngine::new());
    check_chacha20_256_bit_key_vector(ChaChaEngine::new());
    #[cfg(feature = "rustcrypto")]
    check_chacha20_256_bit_key_vector(tc_chacha::ChaChaRustCryptoEngine::new());
}

fn check_rfc_8439_vector<E: Engine>(engine: E) {
    let key = unhex("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f");
    let iv = unhex("000000000000004a00000000");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = unhex(
        "6e2e359a2568f98041ba0728dd0d6981 e97e7aec1d4360c20a27afccfd9fae0b
         f91b65c5524733ab8f593dabcd62b357 1639d624e65152ab8f530c359f0861d8
         07ca0dbf500d6a6156a38e088a22b65e 52bc514d16ccf806818ce91ab7793736
         5af90bbf74a35be6b40b8eedf2785e42 874d",
    );
    assert_eq!(
        encrypt_from_block_one(engine, &key, &iv, plaintext),
        expected
    );
}

#[test]
fn ietf_chacha20_matches_the_rfc_8439_encryption_example() {
    check_rfc_8439_vector(ChaCha7539PortableEngine::new());
    check_rfc_8439_vector(ChaCha7539Engine::new());
    #[cfg(feature = "rustcrypto")]
    check_rfc_8439_vector(tc_chacha::ChaCha7539RustCryptoEngine::new());
}

fn check_xchacha20_vector<E: Engine>(engine: E) {
    let key = unhex("808182838485868788898a8b8c8d8e8f 909192939495969798999a9b9c9d9e9f");
    let iv = unhex("404142434445464748494a4b4c4d4e4f 5051525354555657");
    let plaintext = unhex(
        "4c616469657320616e642047656e746c 656d656e206f662074686520636c6173
         73206f66202739393a20496620492063 6f756c64206f6666657220796f75206f
         6e6c79206f6e652074697020666f7220 746865206675747572652c2073756e73
         637265656e20776f756c642062652069 742e",
    );
    let expected = unhex(
        "bd6d179d3e83d43b9576579493c0e939 572a1700252bfaccbed2902c21396cbb
         731c7f1b0b4aa6440bf3a82f4eda7e39 ae64c6708c54c216cb96b72e1213b452
         2f8c9ba40db5d945b11b69b982c1bb9e 3f3fac2bc369488f76b2383565d3fff9
         21f9664c97637da9768812f615c68b13 b52e",
    );
    assert_eq!(
        encrypt_from_block_one(engine, &key, &iv, &plaintext),
        expected
    );
}

#[test]
fn xchacha20_matches_the_draft_encryption_example() {
    check_xchacha20_vector(XChaCha20PortableEngine::new());
    check_xchacha20_vector(XChaCha20Engine::new());
    #[cfg(feature = "rustcrypto")]
    check_xchacha20_vector(tc_chacha::XChaCha20RustCryptoEngine::new());
}

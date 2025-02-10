use wasm_bindgen::prelude::*;
use zip::read::ZipArchive;
use quick_xml::Reader;
use base64;
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey, Pkcs1v15Decrypt};
use aes::cipher::{KeyIvInit, generic_array::GenericArray, BlockDecryptMut, KeyInit};
use aes::Aes128;
use cbc::Decryptor;
use std::io::Cursor;

// WASM-exposed function
#[wasm_bindgen]
pub fn decrypt_epub(userkey_base64: &str, epub_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    // Step 1: Decode the user key
    let userkey = base64::decode(userkey_base64).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Step 2: Open ZIP archive (EPUB file)
    let reader = Cursor::new(epub_bytes);
    let mut archive = ZipArchive::new(reader).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Step 3: Extract rights.xml
    let mut rights_file = archive.by_name("META-INF/rights.xml")
        .map_err(|_| JsValue::from_str("rights.xml not found"))?;
    let mut rights_xml = String::new();
    rights_file.read_to_string(&mut rights_xml).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Step 4: Extract encryption.xml
    let mut encryption_file = archive.by_name("META-INF/encryption.xml")
        .map_err(|_| JsValue::from_str("encryption.xml not found"))?;
    let mut encryption_xml = String::new();
    encryption_file.read_to_string(&mut encryption_xml).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Step 5: Parse XML and extract encryption key
    let bookkey = extract_encryption_key(&rights_xml)?;

    // Step 6: Decrypt EPUB files
    let decrypted_epub = decrypt_epub_files(&mut archive, &bookkey)?;

    Ok(decrypted_epub)
}

// Function to extract encryption key from rights.xml
fn extract_encryption_key(xml: &str) -> Result<Vec<u8>, JsValue> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);
    
    let mut bookkey_base64 = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event(&mut buf) {
            Ok(quick_xml::events::Event::Text(e)) => {
                let text = e.unescape_and_decode(&reader).unwrap();
                if text.len() > 100 { // Rough check for encryption key
                    bookkey_base64 = Some(text);
                    break;
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(JsValue::from_str(&e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    let bookkey = base64::decode(bookkey_base64.ok_or("Encryption key not found")?)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(bookkey)
}

// Function to decrypt EPUB files using AES
fn decrypt_epub_files(archive: &mut ZipArchive<Cursor<&[u8]>>, bookkey: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut output_zip = vec![];
    let writer = Cursor::new(&mut output_zip);
    let mut new_archive = zip::write::ZipWriter::new(writer);

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let mut content = vec![];
        file.read_to_end(&mut content).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let decrypted_data = if file.name().ends_with(".xml") {
            decrypt_aes_cbc(&content, bookkey)?
        } else {
            content
        };

        new_archive.start_file(file.name(), zip::write::FileOptions::default()).unwrap();
        new_archive.write_all(&decrypted_data).unwrap();
    }

    new_archive.finish().unwrap();

    Ok(output_zip)
}

// AES decryption function
fn decrypt_aes_cbc(data: &[u8], key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let key = GenericArray::from_slice(&key[0..16]);
    let iv = GenericArray::from_slice(&[0; 16]);

    let mut buffer = data.to_vec();
    let cipher = Decryptor::<Aes128>::new(key, iv);
    cipher.decrypt_padded_mut::<cbc::Pkcs7>(&mut buffer)
        .map_err(|_| JsValue::from_str("AES decryption failed"))?;

    Ok(buffer)
}

use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::SecretKey;
use rand_core::OsRng;
use bs58;
use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use rand::Rng;
use generic_array::GenericArray;
use serde_json::Value;
use std::fs;

fn add_padding(text: &str, block_size: usize) -> String {
    let padding_size = block_size - (text.len() % block_size);
    let padding_char = char::from(padding_size as u8);
    let padding = padding_char.to_string().repeat(padding_size);
    format!("{}{}", text, padding)
}

// fn remove_padding(text: &str) -> String {
//     let last_char = text.chars().last().unwrap();
//     let padding_size = last_char as usize;
//     text[..text.len() - padding_size].to_string()
// }

fn main() {
    // 秘密鍵を生成
    let secret_key = SecretKey::random(&mut OsRng);

    // 秘密鍵から署名鍵を生成
    let signing_key = SigningKey::from(&secret_key);

    // 署名鍵から公開鍵を生成
    let public_key = VerifyingKey::from(&signing_key);

    // 秘密鍵をバイト配列に変換
    let secret_key_bytes = secret_key.to_bytes();

    // 公開鍵をバイト配列に変換
    let encoded_point = public_key.to_encoded_point(false);
    let public_key_bytes = encoded_point.as_bytes();

    // 秘密鍵をBase58でエンコード
    let secret_key_base58 = bs58::encode(&secret_key_bytes).into_string();

    // 公開鍵をBase58でエンコード
    let public_key_base58 = bs58::encode(&public_key_bytes).into_string();

    // 秘密鍵と公開鍵をBase58でエンコードした文字列として表示
    println!("Secret Key (Base58): {}", secret_key_base58);
    println!("Public Key (Base58): {}", public_key_base58);

    // メッセージを入力
    println!("Enter a message to encrypt:");
    let mut message = String::new();
    std::io::stdin().read_line(&mut message).expect("Failed to read message");

    // 秘密鍵をBase58からデコード
    let decoded_secret_key = bs58::decode(&secret_key_base58).into_vec().unwrap();

    // 秘密鍵をAES-GCMの鍵として使用
    let key = GenericArray::from_slice(&decoded_secret_key[..32]); // <- この行を修正
    let cipher = Aes256Gcm::new(key);

    // ランダムなnonceを生成
    let mut rng = rand::thread_rng();
    let nonce: [u8; 12] = rng.gen();

    // メッセージを暗号化
    let ciphertext = cipher.encrypt(&nonce.into(), message.as_bytes()).expect("Encryption failed");

     // 暗号文をBase58でエンコード
    let encoded_ciphertext = bs58::encode(&ciphertext).into_string();

    // 暗号化されたメッセージを表示
    println!("Encrypted Message (Base58): {}", encoded_ciphertext);

    // 季語のJSONファイルを読み込む
    let kigo_json = match fs::read_to_string("kigo.json") {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Failed to read kigo.json: {}", e);
            return;
        }
    };

    let kigo_data: Value = match serde_json::from_str(&kigo_json) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to parse JSON: {}", e);
            return;
        }
    };

    // 暗号文を季語に置き換える
let mut kigo_message = String::new();

let padded_ciphertext = add_padding(&encoded_ciphertext, 3);

for (i, c) in padded_ciphertext.char_indices() {
    if i % 3 == 0 {
        if let Some(season_id) = kigo_data["base58"]
            .as_object()
            .unwrap()
            .iter()
            .find_map(|(k, v)| {
                if v.as_array().unwrap().contains(&Value::String(c.to_string())) {
                    k.parse::<usize>().ok()
                } else {
                    None
                }
            })
        {
            let base58_values = kigo_data["base58"][season_id.to_string()]
                .as_array()
                .unwrap();

            let index1 = base58_values
                .iter()
                .position(|v| v == &Value::String(padded_ciphertext[i + 1..i + 2].to_string()))
                .unwrap_or(0);

            let index2 = base58_values
                .iter()
                .position(|v| v == &Value::String(padded_ciphertext[i + 2..i + 3].to_string()))
                .unwrap_or(0);

            let kigo_index = index1 * base58_values.len() + index2;

            if let Some(kigo) = kigo_data["seasons"][season_id]["kigo"]
                .as_array()
                .unwrap()
                .get(kigo_index)
            {
                kigo_message.push_str(kigo.as_str().unwrap());
                kigo_message.push(' ');
            } else {
                kigo_message.push_str(&padded_ciphertext[i..i + 3]);
                kigo_message.push(' ');
            }
        } else {
            kigo_message.push_str(&padded_ciphertext[i..i + 3]);
            kigo_message.push(' ');
        }
    }
}



    // 季語に置き換えたメッセージを表示
    println!("Kigo Message: {}", kigo_message);


    // 暗号文をBase58からデコード
    let decoded_ciphertext = bs58::decode(&encoded_ciphertext).into_vec().unwrap();

    // 暗号文を復号
    let decrypted_message = cipher.decrypt(&nonce.into(), decoded_ciphertext.as_slice()).expect("Decryption failed");

    // 復号されたメッセージを文字列に変換して表示
    let decrypted_message_str = String::from_utf8(decrypted_message).expect("Invalid UTF-8");
    println!("Decrypted Message: {}", decrypted_message_str);
}
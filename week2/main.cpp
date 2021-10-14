#include <cassert>
#include <botan/block_cipher.h>
#include <botan/hex.h>
#include <botan/cipher_mode.h>
#include <botan/bigint.h>
#include <iostream>

void print_vector(Botan::secure_vector<uint8_t>& vec) {
    for(int i =0; i < vec.size(); i++) {
        printf("%c", vec[i]);
    }
    printf("\n");
}

Botan::secure_vector<uint8_t>
my_aes_ctr_decrypt(Botan::secure_vector<uint8_t>& key, Botan::secure_vector<uint8_t>& iv, Botan::secure_vector<uint8_t>& ct) {
    Botan::secure_vector<uint8_t> output;
    output.resize(ct.size() - 16);

    auto cipher(Botan::BlockCipher::create("AES-128"));
    cipher->set_key(key);

    auto bs = cipher->block_size();
    auto it = ct.begin() + 16;
    auto out = output.begin();
    auto prev = iv.begin();

    std::vector<uint8_t> buf;
    buf.resize(16);
    memcpy(buf.data(), iv.data(), 16);

    for(auto i = 0; i < (ct.size())/bs; i++) {

        cipher->encrypt(buf.data(), &(*out));

        // XOR with ciphertext
        for(auto ii = out; ii < out + 16; ii++) {
            *ii ^= *it;
            it++;
        }

        out += 16;

        Botan::BigInt intiv(buf.data(), 16);
        intiv += 1;
        //std::cout << intiv.to_hex_string() << std::endl;
        intiv.binary_encode(buf.data(), 16);

    }

    return output;
}

Botan::secure_vector<uint8_t>
my_aes_cbc_decrypt(Botan::secure_vector<uint8_t>& key, Botan::secure_vector<uint8_t>& iv, Botan::secure_vector<uint8_t>& ct) {
    Botan::secure_vector<uint8_t> output;
    output.resize(ct.size() - 16);

    auto cipher(Botan::BlockCipher::create("AES-128"));

#if 0
    {
    // Compare with lib
    Botan::secure_vector<uint8_t> my_out(ct.begin()+16, ct.end());
    auto enc(Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::DECRYPTION));
    enc->set_key(key);
    enc->start(iv);
    enc->finish(my_out);
    //printf("%d\n", ct2.size());
    std::cout << Botan::hex_encode(my_out) << std::endl;
    //std::cout << enc->name() << "with iv "  << Botan::hex_encode(iv) << " " << Botan::hex_encode(ct2) << std::endl;
    }
#endif

    cipher->set_key(key);

    auto bs = cipher->block_size();
    auto it = ct.begin() + 16;
    auto out = output.begin();
    auto prev = iv.begin();
    for(auto i = 0; i < (ct.size() - bs)/bs; i++) {
        if (i > 0) {
            prev = it - 16;
        }

        cipher->decrypt(&(*it), &(*out));

        for (auto ii = out; ii < out + 16; ii++) {
            *ii ^= *prev;
            prev++;
        }

        it += 16;
        out += 16;
     }

    uint8_t pad_byte = output.back();
    output.resize(output.size() - pad_byte);


    return output;
}


Botan::secure_vector<uint8_t>
my_aes_cbc_encrypt(Botan::secure_vector<uint8_t>& key, Botan::secure_vector<uint8_t>& iv, Botan::secure_vector<uint8_t>& ct) {
    auto old_size = ct.size();
    auto new_size = (ct.size() + 16) & ~(16 - 1);
    //printf("old %d new %d\n", old_size, new_size);
    ct.resize(new_size, new_size - old_size);

    Botan::secure_vector<uint8_t> output;
    output.resize(new_size - 16);

    auto cipher(Botan::BlockCipher::create("AES-128"));

#if 0
    // Compare with lib
    Botan::secure_vector<uint8_t> ct2(ct.begin()+16, ct.end() - 16);
    auto enc(Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::ENCRYPTION));
    enc->set_key(key);
    enc->start(iv);
    enc->finish(ct2);
    printf("%d\n", ct2.size());
    std::cout << Botan::hex_encode(ct2) << std::endl;
    //std::cout << enc->name() << "with iv "  << Botan::hex_encode(iv) << " " << Botan::hex_encode(ct2) << std::endl;
#endif

    cipher->set_key(key);

    auto bs = cipher->block_size();
    auto it = ct.begin() + 16;
    auto out = output.begin();
    auto prev = iv.begin();
    for(auto i = 0; i < (ct.size() - bs)/bs; i++) {
        if (i > 0) {
            prev = out - 16;
        }
#if 0
        std::transform(it, it+16, prev, prev+16, [](auto v1, auto v2) {
            return (v1 ^ v2);
        });

        for (auto j =it; j < it + 16; j++) {
            printf("%x ", *j);
        }
        printf("\n");
#endif

        for (auto ii = it; ii < it + 16; ii++) {
            *ii ^= *prev;
            prev++;
        }

        cipher->encrypt(&(*it), &(*out));
        it += 16;
        out += 16;
     }


    return output;
}

int main() {
    {
        // Key
        Botan::secure_vector<uint8_t> key = Botan::hex_decode_locked("140b41b22a29beb4061bda66b6747e14");
        // IV + CT
        Botan::secure_vector<uint8_t> ct = Botan::hex_decode_locked("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81");
        Botan::secure_vector<uint8_t> iv(ct.begin(), ct.begin() + 16);

        auto output = my_aes_cbc_decrypt(key, iv, ct);

        //std::cout << Botan::hex_encode(output, false) << std::endl;
        //for(int i = 0; i < output.size(); i++ ){
            //printf("%s", (const char *) output.data());
        //}
        //printf("\n");
        print_vector(output);
    }

    {
        // Key
        Botan::secure_vector<uint8_t> key = Botan::hex_decode_locked("140b41b22a29beb4061bda66b6747e14");
        // IV + CT
        Botan::secure_vector<uint8_t> ct = Botan::hex_decode_locked("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253");
        Botan::secure_vector<uint8_t> iv(ct.begin(), ct.begin() + 16);

        auto output = my_aes_cbc_decrypt(key, iv, ct);

        //std::cout << Botan::hex_encode(output, false) << std::endl;
        //printf("%s", (const char *) output.data());
        print_vector(output);
    }

    {
        // Key
        Botan::secure_vector<uint8_t> key = Botan::hex_decode_locked("36f18357be4dbd77f050515c73fcf9f2");
        // IV + CT
        Botan::secure_vector<uint8_t> ct = Botan::hex_decode_locked("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329");
        Botan::secure_vector<uint8_t> iv(ct.begin(), ct.begin() + 16);

        auto output = my_aes_ctr_decrypt(key, iv, ct);

        //std::cout << Botan::hex_encode(output, false) << std::endl;
        //printf("%s\n", (const char *) output.data());
        print_vector(output);

    }

    {
        // Key
        Botan::secure_vector<uint8_t> key = Botan::hex_decode_locked("36f18357be4dbd77f050515c73fcf9f2");
        // IV + CT
        Botan::secure_vector<uint8_t> ct = Botan::hex_decode_locked("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451");
        Botan::secure_vector<uint8_t> iv(ct.begin(), ct.begin() + 16);

        auto output = my_aes_ctr_decrypt(key, iv, ct);

        printf("%s\n", (const char *) output.data());
        //std::cout << Botan::hex_encode(output, false) << std::endl;
    }


    return 0;
}

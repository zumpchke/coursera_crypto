#include <cassert>
#include <botan/block_cipher.h>
#include <botan/hex.h>
#include <botan/cipher_mode.h>
#include <iostream>
#include <botan/mode_pad.h>


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

        auto output = my_aes_cbc_encrypt(key, iv, ct);

        std::cout << Botan::hex_encode(output, false) << std::endl;
    }

    {
        // Key
        Botan::secure_vector<uint8_t> key = Botan::hex_decode_locked("140b41b22a29beb4061bda66b6747e14");
        // IV + CT
        Botan::secure_vector<uint8_t> ct = Botan::hex_decode_locked("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253");
        Botan::secure_vector<uint8_t> iv(ct.begin(), ct.begin() + 16);

        auto output = my_aes_cbc_encrypt(key, iv, ct);

        std::cout << Botan::hex_encode(output, false) << std::endl;
    }


    return 0;
}

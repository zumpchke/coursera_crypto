#include <iostream>
#include <fstream>
#include <cassert>
#include <botan/hex.h>
#include <botan/hash.h>


struct hashed_chunk {
    uint32_t data_size;
    uint8_t *data;
};

struct overlay {
    uint8_t data[1024];
    uint8_t hash[32];
};

void
free_chunks(struct hashed_chunk *chunks, size_t len) {
    for(auto i = 0; i < len; i++) {
        struct hashed_chunk *chunk = &chunks[i];
        free(chunk->data);
    }
}

void
hash_blocks(struct hashed_chunk *chunks, size_t len, uint8_t *h0) 
{
    int i = len - 1;
    auto blocks = 0;
    while (i >= 0) {
        // 
        struct hashed_chunk *ptr = &chunks[i];
        std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
        assert(hash->output_length() == 32);
        // Last block - only hash the data
        if (i == len - 1) {
            //printf("hashing %d\n", ptr->data_size);
            hash->update(ptr->data, ptr->data_size);
        } else {
            // Other blocks, hash the whole block
            hash->update(ptr->data, ptr->data_size + 32);

            struct overlay *o = (struct overlay *) ptr->data;
            //printf("prev block hash @ %p\n", (uint8_t *) o  + 1024);
            //std::cout << Botan::hex_encode((uint8_t *) ptr->data + 1024, 32) << std::endl;
            //assert(0);

        }
        // Need to place in prev block
        auto *prev = ptr - 1;
        if (i == 0) {
            hash->final(h0);
        } else {
            uint8_t *myptr = (uint8_t *) prev->data + prev->data_size;
            //printf("addr of dest %p\n", myptr);
            hash->final(prev->data + prev->data_size);
            //std::cout << Botan::hex_encode((uint8_t *) prev->data + prev->data_size, 32) << std::endl;
        }
        //std::cout << i << std::endl;
        i--;
        blocks++;
    }
     std::cout << "blocks = " << blocks << std::endl;
}

void
verify_chunks(struct hashed_chunk *chunks, size_t len, uint8_t *h0) {
    auto i = 0; 
    uint8_t sha[32] = {0};
    uint8_t *cur_hash = h0;
    for (i = 0; i < len; i++) {
        std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
        if (i == len - 1) {
            hash->update(chunks[i].data, chunks[i].data_size);
        } else {
            hash->update(chunks[i].data, chunks[i].data_size + 32);
        }
        hash->final(sha);
        assert(!memcmp(cur_hash, sha, 32));
        cur_hash = (uint8_t *) chunks[i].data + 1024;
    }
}

int main(int argc, char *argv[]) {

    std::ifstream file;
   // file.open("6.2.birthday.mp4_download", std::ifstream::binary);
    file.open("6.1.intro.mp4_download", std::ifstream::binary);
    assert(file.is_open());

    file.seekg(0, std::ios_base::end);
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    auto num_chunks = size/1024 + 1;

    struct hashed_chunk *chunks = (struct hashed_chunk *)malloc(sizeof(struct hashed_chunk)*num_chunks);
    auto total_sz = 0;

    size_t i = 0;
    while (i < size/1024) {
        struct hashed_chunk *chunk = &chunks[i];
        chunk->data = (uint8_t *) malloc(sizeof(uint8_t)*(1024 + 32));
        chunk->data_size = 1024;
        file.read((char *) chunk->data, 1024);
        total_sz += 1024;
        i += 1;
    }

    if (i*1024 < size) {
        struct hashed_chunk *chunk = &chunks[i];
        auto sz = size - i*1024;
        chunk->data = (uint8_t *) malloc(sizeof(uint8_t)*(sz + 32));
        chunk->data_size = sz;
        file.read((char *) chunk->data, sz);
        total_sz += sz;
    }

    std::vector<uint8_t> h0(32);
    hash_blocks(chunks, num_chunks, h0.data());
    std::cout << "h0 = " << Botan::hex_encode(h0, false) << std::endl;

    verify_chunks(chunks, num_chunks, h0.data());

    free_chunks(chunks, num_chunks);
    free(chunks);

    return 0;
}

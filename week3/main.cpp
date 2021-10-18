#include <iostream>
#include <fstream>
#include <cassert>
#include <botan/hex.h>
#include <botan/hash.h>

#define CHUNK_SIZE      (1024)
#define HASH_SIZE       (32)

struct hashed_chunk {
    uint32_t data_size;
    uint8_t *data;
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
        struct hashed_chunk *ptr = &chunks[i];
        std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
        assert(hash->output_length() == HASH_SIZE);
        // Last block - only hash the data
        if (i == len - 1) {
            hash->update(ptr->data, ptr->data_size);
        } else {
            // Other blocks, hash the whole block
            hash->update(ptr->data, ptr->data_size + HASH_SIZE);
        }
        // Need to place in prev block
        auto *prev = ptr - 1;
        if (i == 0) {
            hash->final(h0);
        } else {
            uint8_t *myptr = (uint8_t *) prev->data + prev->data_size;
            hash->final(prev->data + prev->data_size);
        }
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
            hash->update(chunks[i].data, chunks[i].data_size + HASH_SIZE);
        }
        hash->final(sha);
        assert(!memcmp(cur_hash, sha, HASH_SIZE));
        cur_hash = (uint8_t *) chunks[i].data + 1024;
    }
}

void build_chunks(struct hashed_chunk *chunks, size_t len, std::ifstream& file,
        size_t file_size, uint32_t *total_sz)
{
    size_t i = 0;
    while (i < file_size/CHUNK_SIZE) {
        struct hashed_chunk *chunk = &chunks[i];
        chunk->data = (uint8_t *) malloc(sizeof(uint8_t)*(CHUNK_SIZE + 32));
        chunk->data_size = CHUNK_SIZE;
        file.read((char *) chunk->data, CHUNK_SIZE);
        *total_sz += CHUNK_SIZE;
        i += 1;
    }

    // Remaining
    if (i*CHUNK_SIZE < file_size) {
        struct hashed_chunk *chunk = &chunks[i];
        auto sz = file_size - i*CHUNK_SIZE;
        chunk->data = (uint8_t *) malloc(sizeof(uint8_t)*(sz + HASH_SIZE));
        chunk->data_size = sz;
        file.read((char *) chunk->data, sz);
        *total_sz += sz;
    }
}

int main(int argc, char *argv[]) {
    std::ifstream file;
    //file.open("6.2.birthday.mp4_download", std::ifstream::binary);
    file.open("6.1.intro.mp4_download", std::ifstream::binary);
    assert(file.is_open());

    // Get size
    file.seekg(0, std::ios_base::end);
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    auto num_chunks = size/CHUNK_SIZE + 1;

    struct hashed_chunk *chunks = (struct hashed_chunk *)
        malloc(sizeof(struct hashed_chunk)*num_chunks);
    uint32_t total_sz = 0;

    build_chunks(chunks, num_chunks, file, size, &total_sz);
    assert(total_sz == size);

    // Hash all blocks from the last block (reverse direction)
    std::vector<uint8_t> h0(32);
    hash_blocks(chunks, num_chunks, h0.data());
    std::cout << "h0 = " << Botan::hex_encode(h0, false) << std::endl;

    // Verify blocks in the forward direction
    verify_chunks(chunks, num_chunks, h0.data());

    free_chunks(chunks, num_chunks);
    free(chunks);

    return 0;
}

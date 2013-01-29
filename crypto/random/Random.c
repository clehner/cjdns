/* vim: set expandtab ts=4 sw=4: */
/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "crypto/random/Random.h"
#include "crypto/random/seed/RandomSeed.h"
#include "memory/Allocator.h"
#include "util/Assert.h"
#include "util/Base32.h"
#include "util/Identity.h"

#include <crypto_hash_sha256.h>
#include <crypto_stream_salsa20.h>

#define BUFFLONGS 8
#define BUFFSIZE (BUFFLONGS * 8)

union Random_SeedGen
{
    struct {
        /** Read directly from the seed supplier, same for the whole run of the program. */
        uint64_t seed[4];

        /** Collected by Random_addRandom(). */
        uint64_t collectedEntropy[4];
    } elements;

    /** Used to generate tempSeed. */
    uint64_t buff[8];
};

struct Random
{
    /** The random seed which is used to generate random numbers. */
    uint64_t tempSeed[4];

    /** Used for getting a unique output each cycle. */
    uint64_t nonce;

    /** buffer of random generated in the last rand cycle. */
    uint64_t buff[BUFFLONGS];

    /** the next number to read out of buff. */
    int nextLong;

    /** A counter which Random_addRandom() uses to rotate the random input. */
    int addRandomCounter;

    /** The seed generator for generating new temporary random seeds. */
    union Random_SeedGen* seedGen;

    /** The collector for getting the original permanent random seed from the operating system. */
    struct RandomSeed* seed;

    Identity
};

/**
 * Add a random number to the entropy pool.
 * 1 bit of entropy is extracted from each call to addRandom(), every 256 calls
 * this function will generate a new temporary seed using the permanent seed and
 * the collected entropy.
 *
 * Worst case scenario, Random_addRandom() is completely broken, the original
 * seed is still used and the nonce is never reset so the only loss is forward secrecy.
 */
void Random_addRandom(struct Random* rand, uint64_t randomNumber)
{
    Identity_check(rand);
    #define rotl(a,b) (((a) << (b)) | ((a) >> (64 - (b))))
    rand->seedGen->elements.collectedEntropy[rand->addRandomCounter & 3] ^=
        rotl(randomNumber, rand->addRandomCounter >> 2);
    if (++rand->addRandomCounter >= 256) {
        crypto_hash_sha256((uint8_t*)rand->tempSeed,
                           (uint8_t*)rand->seedGen->buff,
                           sizeof(union Random_SeedGen));
        rand->addRandomCounter = 0;
    }
}

static void stir(struct Random* rand)
{
    crypto_stream_salsa20_xor((uint8_t*)rand->buff,
                              (uint8_t*)rand->buff,
                              BUFFSIZE,
                              (uint8_t*)&rand->nonce,
                              (uint8_t*)rand->tempSeed);
    rand->nonce++;
    rand->nextLong = 0;
}

static void randomLongs(struct Random* rand, uint64_t* location, int count)
{
    if (count > BUFFLONGS - rand->nextLong) {
        if (count > BUFFLONGS) {
            crypto_stream_salsa20_xor((uint8_t*)location,
                                      (uint8_t*)location,
                                      count * 8,
                                      (uint8_t*)&rand->nonce,
                                      (uint8_t*)rand->tempSeed);
            rand->nonce++;
            return;
        }

        for (; rand->nextLong < BUFFLONGS; count--) {
            *location++ = rand->buff[rand->nextLong++];
        }
        Assert_true(count > 0);
        stir(rand);
    }
    for (; count > 0; count--) {
        *location++ = rand->buff[rand->nextLong++];
    }
    Assert_true(rand->nextLong <= BUFFLONGS);
}

void Random_bytes(struct Random* rand, uint8_t* location, uint64_t count)
{
    crypto_stream_salsa20_xor((uint8_t*)location,
                              (uint8_t*)location,
                              count,
                              (uint8_t*)&rand->nonce,
                              (uint8_t*)rand->tempSeed);
    rand->nonce++;
}

/***** This needs proper testing!
void Random_bytes(struct Random* rand, uint8_t* location, uint64_t count)
{
    Identity_check(rand);

    uint64_t edge;
    randomLongs(rand, &edge, 1);

    // < 8 bytes;
    switch (count) {
        case 7: location[6] = edge;
        case 6: location[5] = edge >> 8;
        case 5: location[4] = edge >> 16;
        case 4: location[3] = edge >> 24;
        case 3: location[2] = edge >> 32;
        case 2: location[1] = edge >> 40;
        case 1: location[0] = edge >> 48;
        case 0:
            Random_addRandom(rand, edge);
            return;
        default: break;
    }

    // align the beginning of the buffer
    if (((uintptr_t)location) % 8) {
        if (((uintptr_t)location) % 4) {
            if (((uintptr_t)location) % 2) {
                *location++ = edge;
                count--;
            }
            Assert_true(!(((uintptr_t)location) % 2));
            *((uint16_t*)location) = edge >> 8;
            location += 2;
            count -= 2;
        }
        Assert_true(!(((uintptr_t)location) % 4));
        *((uint32_t*)location) = edge >> 24;
        location += 4;
        count -= 4;
        Random_addRandom(rand, edge);
        randomLongs(rand, &edge, 1);
        Assert_true(!(((uintptr_t)location) % 8));
    }

    // 64 bit aligned
    randomLongs(rand, (uint64_t*)location, count / 8);
    location += ((count / 8) * 8);
    count -= ((count / 8) * 8);

    // align the end of the buffer
    if (count % 8) {
        if (count % 4) {
            if (count % 2) {
                *location++ = edge;
                count--;
            }
            Assert_true(!(count % 2));
            *((uint16_t*)location) = edge >> 8;
            location += 2;
            count -= 2;
        }
        Assert_true(!(count % 4));
        *((uint32_t*)location) = edge >> 24;
        location += 4;
        count -= 4;
        Random_addRandom(rand, edge);
    }
    Assert_true(count == 0);
}*/

void Random_base32(struct Random* rand, uint8_t* output, uint32_t length)
{
    Identity_check(rand);
    uint64_t index = 0;
    for (;;) {
        uint64_t bin[2];
        randomLongs(rand, bin, 2);
        int ret = Base32_encode(&output[index], length - index, (uint8_t*)bin, 16);
        if (ret == Base32_TOO_BIG || index + ret == length) {
            break;
        }
        index += ret;
    }
    output[length - 1] = '\0';
}

struct Random* Random_new(struct Allocator* alloc, struct Log* logger, struct Except* eh)
{
    struct RandomSeed* rs = RandomSeed_new(NULL, logger, alloc);
    union Random_SeedGen* seedGen = Allocator_calloc(alloc, sizeof(union Random_SeedGen), 1);

    if (RandomSeed_get(rs, seedGen->buff)) {
        Except_raise(eh, Random_new_INIT_FAILED,
                     "Unable to initialize secure random number generator");
    }

    struct Random* rand = Allocator_calloc(alloc, sizeof(struct Random), 1);
    rand->seedGen = seedGen;
    rand->seed = rs;

    Identity_set(rand);
    return rand;
}

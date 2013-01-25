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
#include "benc/String.h"
#include "memory/Allocator.h"
#include "util/platform/Sockaddr.h"
#include "util/platform/libc/strlen.h"
#include "util/Bits.h"
#include "util/Hex.h"

#include <stdint.h>
#include <event2/event.h>

struct Sockaddr_pvt
{
    struct Sockaddr pub;
    struct sockaddr_storage ss;
};

struct Sockaddr_in_pvt
{
    struct Sockaddr pub;
    struct sockaddr_in si;
};
struct Sockaddr_in6_pvt
{
    struct Sockaddr pub;
    struct sockaddr_in6 si;
};

const struct Sockaddr* const Sockaddr_LOOPBACK =
    (const struct Sockaddr*) &((const struct Sockaddr_in_pvt) {
        .pub = { .addrLen = sizeof(struct Sockaddr_in_pvt) },
        .si = {
            .sin_family = AF_INET,
            .sin_addr = { .s_addr = 0x7f000001 }
        }
    });
const struct Sockaddr* const Sockaddr_LOOPBACK6 =
    (const struct Sockaddr*) &((const struct Sockaddr_in6_pvt) {
        .pub = { .addrLen = sizeof(struct Sockaddr_in6_pvt) },
        .si = {
            .sin6_family = AF_INET6,
            .sin6_addr = { .s6_addr = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }}
        }
    });

struct Sockaddr* Sockaddr_fromNative(const void* ss, int addrLen, struct Allocator* alloc)
{
    struct Sockaddr_pvt* out = Allocator_malloc(alloc, addrLen + Sockaddr_OVERHEAD);
    Bits_memcpy(&out->ss, ss, addrLen);
    out->pub.addrLen = addrLen + Sockaddr_OVERHEAD;
    return &out->pub;
}

int Sockaddr_parse(const char* str, struct Sockaddr_storage* out)
{
    int addrLen = Sockaddr_MAXSIZE;
    int ret = evutil_parse_sockaddr_port(str, (struct sockaddr*) out->nativeAddr, &addrLen);
    if (!ret) {
        out->addr.addrLen = addrLen + Sockaddr_OVERHEAD;
    }
    return ret;
}

struct Sockaddr* Sockaddr_clone(const struct Sockaddr* addr, struct Allocator* alloc)
{
    return Sockaddr_fromNative(Sockaddr_asNativeConst(addr),
                               addr->addrLen - Sockaddr_OVERHEAD,
                               alloc);
}

char* Sockaddr_print(struct Sockaddr* sockaddr, struct Allocator* alloc)
{
    if (sockaddr->addrLen < (2 + Sockaddr_OVERHEAD)
        || sockaddr->addrLen > Sockaddr_MAXSIZE + Sockaddr_OVERHEAD) {
        return "invalid";
    }

    struct Sockaddr_pvt* addr = (struct Sockaddr_pvt*) sockaddr;

    void* inAddr;
    uint16_t port;
    switch (addr->ss.ss_family) {
        case AF_INET:
            inAddr = &((struct sockaddr_in*) &addr->ss)->sin_addr;
            port = Endian_bigEndianToHost16(((struct sockaddr_in*)&addr->ss)->sin_port);
            break;
        case AF_INET6:
            inAddr = &((struct sockaddr_in6*) &addr->ss)->sin6_addr;
            port = Endian_bigEndianToHost16(((struct sockaddr_in6*)&addr->ss)->sin6_port);
            break;
        default: {
            uint8_t buff[Sockaddr_MAXSIZE * 2 + 1] = {0};
            Hex_encode(buff, sizeof(buff), (uint8_t*)&addr->ss, sockaddr->addrLen);
            String* out = String_printf(alloc, "unknown (%s)", buff);
            return out->bytes;
        }
    };

    #define BUFF_SZ 64
    char printedAddr[BUFF_SZ] = {0};
    if (!evutil_inet_ntop(addr->ss.ss_family, inAddr, printedAddr, BUFF_SZ - 1)) {
        return "invalid";
    }

    if (port) {
        int totalLength = strlen(printedAddr) + strlen("[]:65535") + 1;
        char* out = Allocator_malloc(alloc, totalLength);
        const char* format = (addr->ss.ss_family == AF_INET6) ? "[%s]:%u" : "%s:%u";
        snprintf(out, totalLength, format, printedAddr, port);
        return out;
    }

    int totalLength = strlen(printedAddr) + 1;
    char* out = Allocator_calloc(alloc, totalLength, 1);
    Bits_memcpy(out, printedAddr, totalLength);
    return out;
}

static uint16_t* getPortPtr(struct Sockaddr* sockaddr)
{
    if (sockaddr->addrLen < (2 + Sockaddr_OVERHEAD)) {
        return NULL;
    }
    struct Sockaddr_pvt* sa = (struct Sockaddr_pvt*) sockaddr;
    switch (sa->ss.ss_family) {
        case AF_INET: return &((struct sockaddr_in*)&sa->ss)->sin_port;
        case AF_INET6: return &((struct sockaddr_in6*)&sa->ss)->sin6_port;
    }
    return NULL;
}

int Sockaddr_getPort(struct Sockaddr* sockaddr)
{
    uint16_t* pp = getPortPtr(sockaddr);
    return (pp) ? Endian_bigEndianToHost16(*pp) : -1;
}

int Sockaddr_setPort(struct Sockaddr* sockaddr, uint16_t port)
{
    uint16_t* pp = getPortPtr(sockaddr);
    if (pp) {
        *pp = Endian_hostToBigEndian16(port);
        return 0;
    }
    return -1;
}

int Sockaddr_getAddress(struct Sockaddr* sockaddr, void* addrPtr)
{
    if (sockaddr->addrLen < (2 + Sockaddr_OVERHEAD)) {
        return -1;
    }
    struct Sockaddr_pvt* sa = (struct Sockaddr_pvt*) sockaddr;
    if (addrPtr) {
        void** ap = (void**) addrPtr;
        switch (sa->ss.ss_family) {
            case AF_INET: *ap = &((struct sockaddr_in*)&sa->ss)->sin_addr; break;
            case AF_INET6: *ap = &((struct sockaddr_in6*)&sa->ss)->sin6_addr; break;
        }
    }
    switch (sa->ss.ss_family) {
        case AF_INET: return 4;
        case AF_INET6: return 16;
    }
    return -1;
}

const int Sockaddr_AF_INET = AF_INET;
const int Sockaddr_AF_INET6 = AF_INET6;
int Sockaddr_getFamily(struct Sockaddr* sockaddr)
{
    if (sockaddr->addrLen < (2 + Sockaddr_OVERHEAD)) {
        return -1;
    }
    struct Sockaddr_pvt* sa = (struct Sockaddr_pvt*) sockaddr;
    return sa->ss.ss_family;
}

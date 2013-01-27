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
#include "admin/Admin.h"
//#include "admin/angel/Angel.h"
#include "benc/String.h"
#include "benc/Dict.h"
//#include "benc/List.h"
#include "benc/serialization/BencSerializer.h"
#include "benc/serialization/standard/StandardBencSerializer.h"
//#include "dht/CJDHTConstants.h"
//#include "exception/Except.h"
#include "interface/addressable/AddrInterface.h"
#include "io/Reader.h"
#include "io/ArrayReader.h"
#include "io/ArrayWriter.h"
#include "io/Writer.h"
#include "memory/Allocator.h"
#include "memory/BufferAllocator.h"
#include "util/Assert.h"
#include "util/Bits.h"
#include "util/Hex.h"
#include "util/log/Log.h"
//#include "util/Security.h"
#include "util/events/Time.h"
#include "util/Identity.h"
//#include "util/events/Timeout.h"
#include "util/platform/Sockaddr.h"

#define string_strstr
#define string_strcmp
#define string_strlen
#include "util/platform/libc/string.h"

#include <crypto_hash_sha256.h>
//#include <limits.h>
//#include <stdbool.h>
//#include <unistd.h>

#ifdef WIN32
    #define EWOULDBLOCK WSAEWOULDBLOCK
#endif

static String* TYPE =     String_CONST_SO("type");
static String* REQUIRED = String_CONST_SO("required");
static String* STRING =   String_CONST_SO("String");
static String* INTEGER =  String_CONST_SO("Int");
static String* DICT =     String_CONST_SO("Dict");
static String* LIST =     String_CONST_SO("List");
static String* TXID =     String_CONST_SO("txid");

struct Function
{
    String* name;
    Admin_FUNCTION(call);
    void* context;
    bool needsAuth;
    Dict* args;
};

struct Admin
{
    struct EventBase* eventBase;

    struct Function* functions;
    int functionCount;

    struct Allocator* allocator;

    String* password;
    struct Log* logger;

    struct AddrInterface* iface;

    /** Length of addresses of clients which communicate with admin. */
    uint32_t addrLen;

    Identity
};

static uint8_t sendMessage(struct Message* message, struct Sockaddr* dest, struct Admin* admin)
{
    // stack overflow when used with admin logger.
    //Log_keys(admin->logger, "sending message to angel [%s]", message->bytes);
    Message_push(message, dest, dest->addrLen);
    return admin->iface->generic.sendMessage(message, &admin->iface->generic);
}

static int sendBenc(Dict* message, struct Sockaddr* dest, struct Admin* admin)
{
    struct Allocator* allocator;
    BufferAllocator_STACK(allocator, 256);

    #define SEND_MESSAGE_PADDING 32
    uint8_t buff[Admin_MAX_RESPONSE_SIZE + SEND_MESSAGE_PADDING];

    struct Writer* w = ArrayWriter_new(buff + SEND_MESSAGE_PADDING,
                                       Admin_MAX_RESPONSE_SIZE,
                                       allocator);
    StandardBencSerializer_get()->serializeDictionary(w, message);

    struct Message m = {
        .bytes = buff + SEND_MESSAGE_PADDING,
        .length = w->bytesWritten(w),
        .padding = SEND_MESSAGE_PADDING
    };
    return sendMessage(&m, dest, admin);
}

/**
 * public function to send responses
 */
int Admin_sendMessage(Dict* message, String* txid, struct Admin* admin)
{
    if (!admin) {
        return 0;
    }
    Identity_check(admin);
    Assert_true(txid && txid->len >= admin->addrLen);

    struct Sockaddr_storage addr;
    Bits_memcpy(&addr, txid->bytes, admin->addrLen);

    struct Allocator* allocator;
    BufferAllocator_STACK(allocator, 256);

    // Bounce back the user-supplied txid.
    String userTxid = {
        .bytes = txid->bytes + admin->addrLen,
        .len = txid->len - admin->addrLen
    };
    if (txid->len > admin->addrLen) {
        Dict_putString(message, TXID, &userTxid, allocator);
    }

    return sendBenc(message, &addr.addr, admin);
}

static inline bool authValid(Dict* message, struct Message* messageBytes, struct Admin* admin)
{
    String* cookieStr = Dict_getString(message, String_CONST("cookie"));
    uint32_t cookie = (cookieStr != NULL) ? strtoll(cookieStr->bytes, NULL, 10) : 0;
    if (!cookie) {
        int64_t* cookieInt = Dict_getInt(message, String_CONST("cookie"));
        cookie = (cookieInt) ? *cookieInt : 0;
    }
    uint64_t nowSecs = Time_currentTimeSeconds(admin->eventBase);
    String* submittedHash = Dict_getString(message, String_CONST("hash"));
    if (cookie >  nowSecs || cookie < nowSecs - 20 || !submittedHash || submittedHash->len != 64) {
        return false;
    }

    uint8_t* hashPtr = (uint8_t*) strstr((char*) messageBytes->bytes, submittedHash->bytes);

    if (!hashPtr || !admin->password) {
        return false;
    }

    uint8_t passAndCookie[64];
    snprintf((char*) passAndCookie, 64, "%s%u", admin->password->bytes, cookie);
    uint8_t hash[32];
    crypto_hash_sha256(hash, passAndCookie, strlen((char*) passAndCookie));
    Hex_encode(hashPtr, 64, hash, 32);

    crypto_hash_sha256(hash, messageBytes->bytes, messageBytes->length);
    Hex_encode(hashPtr, 64, hash, 32);
    return Bits_memcmp(hashPtr, submittedHash->bytes, 64) == 0;
}

static bool checkArgs(Dict* args, struct Function* func, String* txid, struct Admin* admin)
{
    struct Dict_Entry* entry = *func->args;
    String* error = NULL;
    uint8_t buffer[1024];
    struct Allocator* alloc = BufferAllocator_new(buffer, 1024);
    while (entry != NULL) {
        String* key = (String*) entry->key;
        Assert_true(entry->val->type == Object_DICT);
        Dict* value = entry->val->as.dictionary;
        entry = entry->next;
        if (*Dict_getInt(value, String_CONST("required")) == 0) {
            continue;
        }
        String* type = Dict_getString(value, String_CONST("type"));
        if ((type == STRING && !Dict_getString(args, key))
            || (type == DICT && !Dict_getDict(args, key))
            || (type == INTEGER && !Dict_getInt(args, key))
            || (type == LIST && !Dict_getList(args, key)))
        {
            error = String_printf(alloc,
                                  "Entry [%s] is required and must be of type [%s]",
                                  key->bytes,
                                  type->bytes);
            break;
        }
    }
    if (error) {
        Dict d = Dict_CONST(String_CONST("error"), String_OBJ(error), NULL);
        Admin_sendMessage(&d, txid, admin);
    }
    return !error;
}

static void handleRequest(Dict* messageDict,
                          struct Message* message,
                          struct Sockaddr* src,
                          struct Allocator* allocator,
                          struct Admin* admin)
{
    String* query = Dict_getString(messageDict, String_CONST("q"));
    if (!query) {
        Log_info(admin->logger, "Got a non-query from admin interface");
        return;
    }

    // txid becomes the user supplied txid combined with the channel num.
    String* userTxid = Dict_getString(messageDict, TXID);
    uint32_t txidlen = ((userTxid) ? userTxid->len : 0) + src->addrLen;
    String* txid = String_newBinary(NULL, txidlen, allocator);
    Bits_memcpy(txid->bytes, src, src->addrLen);
    if (userTxid) {
        Bits_memcpy(txid->bytes + src->addrLen, userTxid->bytes, userTxid->len);
    }

    // If they're asking for a cookie then lets give them one.
    String* cookie = String_CONST("cookie");
    if (String_equals(query, cookie)) {
        Log_debug(admin->logger, "Got a request for a cookie");
        Dict* d = Dict_new(allocator);
        char bytes[32];
        snprintf(bytes, 32, "%u", (uint32_t) Time_currentTimeSeconds(admin->eventBase));
        String* theCookie = &(String) { .len = strlen(bytes), .bytes = bytes };
        Dict_putString(d, cookie, theCookie, allocator);
        Admin_sendMessage(d, txid, admin);
        return;
    }

    // If this is a permitted query, make sure the cookie is right.
    String* auth = String_CONST("auth");
    bool authed = false;
    if (String_equals(query, auth)) {
        if (!authValid(messageDict, message, admin)) {
            Dict* d = Dict_new(allocator);
            Dict_putString(d, String_CONST("error"), String_CONST("Auth failed."), allocator);
            Admin_sendMessage(d, txid, admin);
            return;
        }
        query = Dict_getString(messageDict, String_CONST("aq"));
        authed = true;
    }

    Dict* args = Dict_getDict(messageDict, String_CONST("args"));
    bool noFunctionsCalled = true;
    for (int i = 0; i < admin->functionCount; i++) {
        if (String_equals(query, admin->functions[i].name)
            && (authed || !admin->functions[i].needsAuth))
        {
            if (checkArgs(args, &admin->functions[i], txid, admin)) {
                admin->functions[i].call(args, admin->functions[i].context, txid);
            }
            noFunctionsCalled = false;
        }
    }

    if (noFunctionsCalled) {
        Dict* d = Dict_new(allocator);
        String* list = String_CONST("availableFunctions");
        if (!String_equals(query, list)) {
            Dict_putString(d,
                           String_CONST("error"),
                           String_CONST("No functions matched your request."),
                           allocator);
        }
        Dict* functions = Dict_new(allocator);
        for (int i = 0; i < admin->functionCount; i++) {
            Dict_putDict(functions, admin->functions[i].name, admin->functions[i].args, allocator);
        }
        if (functions) {
            Dict_putDict(d, String_CONST("availableFunctions"), functions, allocator);
        }
        Admin_sendMessage(d, txid, admin);
        return;
    }

    return;
}

static void handleMessage(struct Message* message,
                          struct Sockaddr* src,
                          struct Allocator* alloc,
                          struct Admin* admin)
{
    message->bytes[message->length] = '\0';
    Log_debug(admin->logger, "Got message from [%s] [%s]",
              Sockaddr_print(src, alloc), message->bytes);

    // handle non empty message data
    if (message->length > Admin_MAX_REQUEST_SIZE) {
        #define TOO_BIG "d5:error16:Request too big.e"
        #define TOO_BIG_STRLEN (sizeof(TOO_BIG) - 1)
        Bits_memcpyConst(message->bytes, TOO_BIG, TOO_BIG_STRLEN);
        message->length = TOO_BIG_STRLEN;
        sendMessage(message, src, admin);
        return;
    }

    struct Reader* reader = ArrayReader_new(message->bytes, message->length, alloc);
    Dict messageDict;
    if (StandardBencSerializer_get()->parseDictionary(reader, alloc, &messageDict)) {
        Log_warn(admin->logger,
                 "Unparsable data from [%s] content: [%s]",
                 Sockaddr_print(src, alloc), message->bytes);
        return;
    }

    int amount = reader->bytesRead(reader);
    if (amount < message->length) {
        Log_warn(admin->logger,
                 "Message from [%s] contained garbage after byte [%d] content: [%s]",
                 Sockaddr_print(src, alloc), amount - 1, message->bytes);
        return;
    }

    handleRequest(&messageDict, message, src, alloc, admin);
}

static uint8_t receiveMessage(struct Message* message, struct Interface* iface)
{
    struct Admin* admin = Identity_cast((struct Admin*) iface->receiverContext);

    Assert_true(message->length >= (int)admin->addrLen);
    struct Sockaddr_storage addrStore;
    Message_pop(message, &addrStore, admin->addrLen);

    struct Allocator* alloc = Allocator_child(admin->allocator);
    handleMessage(message, &addrStore.addr, alloc, admin);
    Allocator_free(alloc);
    return 0;
}

void Admin_registerFunctionWithArgCount(char* name,
                                        Admin_FUNCTION(callback),
                                        void* callbackContext,
                                        bool needsAuth,
                                        struct Admin_FunctionArg* arguments,
                                        int argCount,
                                        struct Admin* admin)
{
    if (!admin) {
        return;
    }
    Identity_check(admin);

    String* str = String_new(name, admin->allocator);
    admin->functions =
        Allocator_realloc(admin->allocator,
                          admin->functions,
                          sizeof(struct Function) * (admin->functionCount + 1));
    struct Function* fu = &admin->functions[admin->functionCount];
    admin->functionCount++;

    fu->name = str;
    fu->call = callback;
    fu->context = callbackContext;
    fu->needsAuth = needsAuth;
    fu->args = Dict_new(admin->allocator);
    for (int i = 0; arguments && i < argCount; i++) {
        // "type" must be one of: [ "String", "Int", "Dict", "List" ]
        String* type = NULL;
        if (!strcmp(arguments[i].type, STRING->bytes)) {
            type = STRING;
        } else if (!strcmp(arguments[i].type, INTEGER->bytes)) {
            type = INTEGER;
        } else if (!strcmp(arguments[i].type, DICT->bytes)) {
            type = DICT;
        } else if (!strcmp(arguments[i].type, LIST->bytes)) {
            type = LIST;
        } else {
            abort();
        }
        Dict* arg = Dict_new(admin->allocator);
        Dict_putString(arg, TYPE, type, admin->allocator);
        Dict_putInt(arg, REQUIRED, arguments[i].required, admin->allocator);
        String* name = String_new(arguments[i].name, admin->allocator);
        Dict_putDict(fu->args, name, arg, admin->allocator);
    }
}

struct Admin* Admin_new(struct AddrInterface* iface,
                        struct Allocator* alloc,
                        struct Log* logger,
                        struct EventBase* eventBase,
                        String* password)
{
    struct Admin* admin = Allocator_clone(alloc, (&(struct Admin) {
        .iface = iface,
        .allocator = alloc,
        .logger = logger,
        .eventBase = eventBase,
        .addrLen = iface->addr->addrLen
    }));
    Identity_set(admin);

    admin->password = String_clone(password, alloc),

    iface->generic.receiveMessage = receiveMessage;
    iface->generic.receiverContext = admin;

    return admin;
}

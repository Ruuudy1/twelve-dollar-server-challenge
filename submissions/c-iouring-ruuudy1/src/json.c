// Owner: json module. Strict body parser, unescape, JavaScript-style trim and the escaping writer.

// Type of a field found by json_extract.
enum json_type {
    JSON_ABSENT,
    JSON_STRING,
    JSON_NUMBER,
    JSON_OTHER,
};

// One requested key and what the document held for it; the last duplicate wins.
struct json_field {
    const char *key;
    uint8_t type;
    // True when a string value still contains backslash escapes.
    bool escaped;
    // For strings the bytes between the quotes, still escaped; for numbers the literal text.
    struct slice raw;
    double num;
};

enum json_status {
    JSON_OK,
    JSON_MALFORMED,
    JSON_NOT_OBJECT,
};

// Result of validating a create-post body.
enum json_body_status {
    JSON_BODY_OK,
    JSON_BODY_MALFORMED,
    JSON_BODY_REQUIRED,
    JSON_BODY_TOO_LONG,
};

// Bytes the escaping writer can emit for n input bytes.
#define JSON_ESCAPED_MAX(n) (6 * (size_t)(n))

// Validates the whole document as RFC 8259 JSON and fills the requested top-level fields of an object.
static NOT_YET_USED enum json_status json_extract(struct slice doc, struct json_field *fields, unsigned count) {
    (void)doc;
    (void)fields;
    (void)count;
    return JSON_MALFORMED;
}

// Decodes a string body into dst, joining surrogate pairs; returns the length or -1 when cap is too small.
static NOT_YET_USED int64_t json_unescape(struct slice s, char *dst, uint32_t cap) {
    (void)s;
    (void)dst;
    (void)cap;
    return -1;
}

// Trims the JavaScript whitespace set from both ends of UTF-8 text.
static NOT_YET_USED struct slice json_trim_js(struct slice s) {
    return s;
}

// Counts Unicode code points in UTF-8 text.
static NOT_YET_USED uint32_t json_count_chars(struct slice s) {
    uint32_t chars = 0;
    for (uint32_t i = 0; i < s.n; i++) {
        chars += (s.p[i] & 0xC0) != 0x80;
    }
    return chars;
}

// Parses a create body, unescapes and trims its "body" string into scratch, and applies the length rules.
static NOT_YET_USED enum json_body_status json_create_body(struct slice doc, char *scratch, uint32_t cap,
                                                           struct slice *out) {
    (void)doc;
    (void)scratch;
    (void)cap;
    out->p = scratch;
    out->n = 0;
    return JSON_BODY_MALFORMED;
}

// Writes the escaped form of s (without quotes) at o and returns the end; room for JSON_ESCAPED_MAX(n) is required.
static char *json_put_string(char *o, const char *s, size_t n) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c != '"' && c != '\\') {
            *o++ = (char)c;
            continue;
        }
        *o++ = '\\';
        switch (c) {
        case '"':
        case '\\':
            *o++ = (char)c;
            break;
        case '\b':
            *o++ = 'b';
            break;
        case '\f':
            *o++ = 'f';
            break;
        case '\n':
            *o++ = 'n';
            break;
        case '\r':
            *o++ = 'r';
            break;
        case '\t':
            *o++ = 't';
            break;
        default:
            *o++ = 'u';
            *o++ = '0';
            *o++ = '0';
            *o++ = hex[c >> 4];
            *o++ = hex[c & 15];
            break;
        }
    }
    return o;
}

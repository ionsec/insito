/* rhysida-esxi-decryptor — victim-ready recovery tool for the Rhysida ESXi/Linux (ELF) strain.
 *
 * Model reverse-engineered from the ELF build (SHA256 be5d2e94c2498ec052fb02
 * 5e3348085e418c856dd43080501acfe2067ba54c41, Ghidra 12.1.4 decompile, 2026-11-06):
 *   - main: srand((uint)time(NULL));  register LTC ciphers;  import RSA-4096
 *     public key from embedded SPKI (this repo's pubkey_elf.h);
 *   - single chacha20 CSPRNG (find_prng("chacha20"), index IDX) constructed ONCE
 *     (FUN_00403364):  chacha20_prng_start/ready, then 40 entropy bytes
 *     ent[i] = ((char)(IDX + i + 1) * (char)(rand() % 0x100))     [glibc rand!],
 *     chacha20_prng_add_entropy(ent,40), then ONE interleaved rand() draw used
 *     for a malloc(rand()%256+1) — followed by an 8-byte self-test draw;
 *   - SINGLE-THREADED: one global stream; per file: draw key[32], iv[16],
 *     AES-256-CTR encrypt in place (chunked), append 0x40C trailer
 *     [keyblob512][len4][ivblob512][len4][type4=1], rename to *.rhysida;
 *     RSA-4096-OAEP(label "Rhysida-0.1") wraps draw their OAEP seed bytes from
 *     the same live stream as the Windows build (replayable).
 * Differences vs the Windows builds of this family: glibc TYPE_3 rand()
 *     (not msvcrt LCG), single slot (no per-slot fast-forward),
 *     sequential sequence scan up to SEQMAX.
 *
 * Oracle: per (seed, seq) reproduce key/IV wrap and match against every file's
 *         own trailer byte-for-byte — NO plaintext needed.
 * Decrypt: AES-256-CTR LITTLE-ENDIAN counter by default (-DBE_COUNTER to flip);
 *          -DAUTO_CTR decrypts LE first, then BE if LE produced no exact match
 *          against an available original.
 */

#include <tomcrypt.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <syslog.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#endif

#ifdef ESXI_KEY
#include "pubkey_elf.h"
#else
#error "compile with -DESXI_KEY (this tool models the ELF build)"
#endif

void crypt_argchk(const char *a, const char *b, int c) { (void)a; (void)b; (void)c; }
extern const ltc_math_descriptor ltm_desc;

#define MAXF 512
#define MAXFNAME 1024
#define MAXFILEBYTES (256u * 1024u * 1024u)
#define SEQMAX 1100          /* per-seq scan ceiling (files encrypted this run) */
#define SWEEP_SEQS 400       /* seq ceiling used to score each seED in sweep mode */

/* ---- exact glibc TYPE_3 rand() (verified vs libc in selftest_glibcrand.c) ---- */
typedef struct { int32_t r[31]; int f, k; } RSTATE;   /* glibc TYPE_3: 31-word state */

static void rs_srand(RSTATE *s, uint32_t seed) {
    int32_t word = (int32_t)seed;
    if (word == 0) word = 1;
    s->r[0] = word;                          /* r[0] = seed */
    for (int i = 1; i <= 30; i++) {          /* 30 Lehmer iterates: r[1..30] */
        int64_t w = 16807L * (int64_t)(word % 127773) - 2836L * (int64_t)(word / 127773);
        if (w < 0) w += 2147483647L;
        word = (int32_t)w;
        s->r[i] = word;
    }
    s->f = 3; s->k = 0;                      /* fptr=state[3], rptr=state[0] */
    for (int i = 0; i < 310; i++) {          /* 310 initial discards */
        s->r[s->f] = (int32_t)((uint32_t)s->r[s->f] + (uint32_t)s->r[s->k]);
        s->f = (s->f + 1) % 31; s->k = (s->k + 1) % 31;
    }
}
static uint32_t rs_rand(RSTATE *s) {
    s->r[s->f] = (int32_t)((uint32_t)s->r[s->f] + (uint32_t)s->r[s->k]);
    uint32_t out = (uint32_t)s->r[s->f] >> 1;
    s->f = (s->f + 1) % 31; s->k = (s->k + 1) % 31;
    return out;
}

static void aes_ctr_dec(const uint8_t key[32], const uint8_t iv16[16],
                        const uint8_t *ct, size_t n, uint8_t *pt) {
    symmetric_key sk;
    aes_setup(key, 32, 0, &sk);
    uint8_t ctrb[16], ks[16];
    memcpy(ctrb, iv16, 16);
    for (size_t i = 0; i < n; i += 16) {
        aes_ecb_encrypt(ctrb, ks, &sk);
#ifdef BE_COUNTER
        for (int j = 15; j >= 0; j--) { ctrb[j] = (uint8_t)(ctrb[j] + 1); if (ctrb[j]) break; }
#else
        for (int j = 0; j < 16; j++) { ctrb[j] = (uint8_t)(ctrb[j] + 1); if (ctrb[j]) break; }
#endif
        size_t take = (n - i < 16) ? (n - i) : 16;
        for (size_t j = 0; j < take; j++) pt[i + j] = ct[i + j] ^ ks[j];
    }
}

static void mk1dir(const char *p) {
#ifdef _WIN32
    _mkdir(p);
#else
    mkdir(p, 0777);
#endif
}

typedef struct {
    char name[MAXFNAME];
    unsigned char *data; long sz;
    unsigned char *orig; long origlen;
    long plainlen;
    int hit_seq; int found;
    unsigned long mtime;
} EF;

/* Build the live chacha stream exactly like FUN_00403364 for one (seed, prng_idx). */
static void build_stream(uint32_t seed, int prng_idx, prng_state *ps) {
    RSTATE rs; rs_srand(&rs, seed);
    unsigned char ent[40];
    for (int i = 0; i < 40; i++) {
        uint32_t rv = rs_rand(&rs) % 0x100ul;
        ent[i] = (unsigned char)(((uint32_t)(prng_idx + i + 1) * rv) % 0x100ul);
    }
    chacha20_prng_start(ps);
    chacha20_prng_ready(ps);
    chacha20_prng_add_entropy(ent, 0x28, ps);
    (void)rs_rand(&rs);                      /* the interleaved malloc-rand draw */
    unsigned char selftest[8];
    chacha20_prng_read(selftest, 8, ps);     /* 8-byte self-test */
}

/* Per (seed): rebuild the stream ONCE, then walk it exactly like the sample:
 * per file draw key32+iv16 (48 B), wrap key (OAEP seed draws consume stream),
 * wrap IV (OAEP seed draws consume stream), repeat — linear position carried
 * inside ps, no positional skips. O(SEQ) wraps per seed. */
static int sweep_seed(uint32_t seed, int prng_idx, int HASH_IDX, rsa_key *pub,
                      EF *ef, int nf, int seqcap) {
    prng_state ps;
    build_stream(seed, prng_idx, &ps);
    int resolved = 0;
    for (int seq = 0; seq <= seqcap; seq++) {
        unsigned char key[32], iv[16];
        chacha20_prng_read(key, 32, &ps);
        chacha20_prng_read(iv, 16, &ps);
        unsigned char blob[0x1000]; unsigned long bloblen = 0x800;
        if (rsa_encrypt_key_ex(key, 32, blob, &bloblen, (unsigned char *)"Rhysida-0.1", 0xb,
                               &ps, prng_idx, HASH_IDX, LTC_PKCS_1_OAEP, pub) != CRYPT_OK)
            continue;
        int keymatch = 0;
        for (int fi = 0; fi < nf; fi++) {
            if (ef[fi].found) continue;
            if (ef[fi].sz < 0x40C) continue;
            const unsigned char *tr = ef[fi].data + (ef[fi].sz - 0x40C);
            unsigned long kl = (unsigned long)tr[0x200] | ((unsigned long)tr[0x201] << 8) |
                               ((unsigned long)tr[0x202] << 16) | ((unsigned long)tr[0x203] << 24);
            unsigned long vl = (unsigned long)tr[0x404] | ((unsigned long)tr[0x405] << 8) |
                               ((unsigned long)tr[0x406] << 16) | ((unsigned long)tr[0x407] << 24);
            if (kl != 512 || vl != 512) continue;
            if (memcmp(tr, blob, 512) == 0) keymatch = 1;
        }
        if (!keymatch) continue;             /* skips the IV wrap on dead candidates */
        unsigned char blob2[0x1000]; unsigned long blob2len = 0x800;
        (void)rsa_encrypt_key_ex(iv, 16, blob2, &blob2len, (unsigned char *)"Rhysida-0.1", 0xb,
                                 &ps, prng_idx, HASH_IDX, LTC_PKCS_1_OAEP, pub);
        for (int fi = 0; fi < nf; fi++) {
            if (ef[fi].found) continue;
            if (ef[fi].sz < 0x40C) continue;
            const unsigned char *tr = ef[fi].data + (ef[fi].sz - 0x40C);
            /* trailer: [keyblob512B][len4][ivblob512B][len4][type4]; blobs are
             * variable-len in theory but 512 == RSA-4096 output here */
            unsigned long kl = (unsigned long)tr[0x200] | ((unsigned long)tr[0x201] << 8) |
                               ((unsigned long)tr[0x202] << 16) | ((unsigned long)tr[0x203] << 24);
            unsigned long vl = (unsigned long)tr[0x404] | ((unsigned long)tr[0x405] << 8) |
                               ((unsigned long)tr[0x406] << 16) | ((unsigned long)tr[0x407] << 24);
            if (kl != 512 || vl != 512) continue;
            if (memcmp(tr, blob, 512) == 0 && memcmp(tr + 0x204, blob2, 512) == 0) {
                ef[fi].found = 1; ef[fi].hit_seq = seq; resolved++;
            }
        }
    }
    return resolved;
}

/* ---- public key carving (for builds with rotated campaign keys) ----
 * The locker binary must carry its own RSA-4096 SPKI. We scan the file for the
 * RSA modulus INTEGER (tag 02, long length 8201, leading 00) and try
 * rsa_import() on the enclosing SPKI window; success = valid key. */
static int carve_spki_from(uint8_t *buf, size_t len, rsa_key *out, unsigned long *at) {
    if (len < 0x200) return -1;
    /* find a 4096-bit INTEGER header 02 82 02 01 00 (leading-zero modulus),
       then walk BACKWARD over possible DER wrappers (BIT STRING / SEQUENCE)
       trying every plausible SubjectPublicKeyInfo span; rsa_import in
       libtomcrypt auto-detects SPKI / RSAPublicKey / PEM-ish DER. */
    for (size_t i = 0; i + 6 <= len; i++) {
        if (buf[i] != 0x02 || buf[i+1] != 0x82 || buf[i+2] != 0x02 ||
            buf[i+3] != 0x01 || buf[i+4] != 0x00) continue;
        int done = 0;
        for (long k = (long)i; k >= (long)(i > 96 ? i - 96 : 0) && !done; k--) {
            if (buf[k] != 0x30 && buf[k] != 0x03) continue;
            if (k + 4 > len) continue;
            unsigned long L = ((unsigned long)buf[k+2] << 8) | (unsigned long)buf[k+3];
            if (L < 0x200 || L > 0x400) continue;
            if ((unsigned long)k + 4 + L > len) continue;
            if (rsa_import(buf + k, L + 4, out) == CRYPT_OK) {
                *at = (unsigned long)k;
                done = 1;
            }
        }
        if (done) return 0;
    }
    return -1;
}

/* ---- raw-key fallback: 512B big-endian modulus ending right before ---- */
/* ---- exponent 01 00 01 (modulus/exp stored without DER) ------------- */
static int carve_raw_from(uint8_t *buf, size_t len, rsa_key *out, unsigned long *at) {
    uint8_t der[256 + 561];
    size_t pos = 0;
    static const uint8_t PFX[22] = {
        0x30, 0x82, 0x02, 0x22,             /* SPKI SEQUENCE 546  */
        0x30, 0x0d,                         /* algorithm SEQUENCE */
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00,
        0x03, 0x82, 0x02, 0x0f              /* BIT STRING 527     */
    };
    if (len < 515) return -1;
    for (size_t i = 511 + 3; i + 0 <= len - 3; i++) {
        if (buf[i] != 0x01 || buf[i+1] != 0x00 || buf[i+2] != 0x01) continue;
        size_t mstart = i - 511;             /* modulus begins at i-511 (512 bytes end at i) */
        const uint8_t *m = buf + mstart;
        if (m[0] < 0x80) continue;           /* 4096-bit modulus: top bit set */
        if ((m[511] & 1) == 0) continue;     /* modulus odd */
        int bad = 0;
        unsigned ones = 0, zeros = 0;
        for (int q = 0; q < 512; q++) { if (m[q] == 0xff) ones++; if (m[q] == 0x00) zeros++; }
        if (ones > 480 || zeros > 480) continue;
        memcpy(der, PFX, 22);
        pos = 22;
        der[pos++] = 0x00;                   /* unused bits */
        der[pos++] = 0x30; der[pos++] = 0x82; der[pos++] = 0x02; der[pos++] = 0x0a;
        der[pos++] = 0x02; der[pos++] = 0x82; der[pos++] = 0x02; der[pos++] = 0x01; der[pos++] = 0x00;
        memcpy(der + pos, m, 512); pos += 512;
        der[pos++] = 0x02; der[pos++] = 0x03; der[pos++] = 0x01; der[pos++] = 0x00; der[pos++] = 0x01;
        if (rsa_import(der, pos, out) == CRYPT_OK) { *at = mstart; return 0; }
    }
    return -1;
}

/* ---- base64/PEM helper for carrier files (ransom notes) ------------- */
static int carve_from_pem(uint8_t *buf, size_t len, rsa_key *out, unsigned long *at) {
    static const char BEG[] = "-----BEGIN PUBLIC KEY-----";
    static const char END[] = "-----END PUBLIC KEY-----";
    static char b64[4096];
    static unsigned char der[1024];
    for (size_t i = 0; i + sizeof BEG < len; i++) {
        if (memcmp(buf + i, BEG, sizeof BEG - 1) != 0) continue;
        size_t start = i + sizeof BEG - 1;
        /* find the marker end BEFORE touching the payload */
        size_t stop = len;
        for (size_t j = start; j + sizeof END - 1 <= len; j++) {
            if (memcmp(buf + j, END, sizeof END - 1) == 0) { stop = j; break; }
        }
        size_t bi = 0;
        for (size_t j = start; j < stop && bi + 2 < sizeof b64; j++) {
            char c = (char)buf[j];
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '+' || c == '/') b64[bi++] = c;
        }
        if (bi < 400) continue;
        while (bi % 4) b64[bi++] = '=';
        unsigned long dlen = sizeof der;
        if (base64_decode((unsigned char *)b64, (unsigned long)bi, der, &dlen) != CRYPT_OK)
            continue;
        if (dlen < 0x200) continue;
        if (carve_spki_from(der, (size_t)dlen, out, at) == 0) return 0;
    }
    return -1;
}

/* ---- recursive .rhysida scan ---- */
static int scan_dir(const char *path, EF *ef, int *nf, int depth, unsigned long *loaded,
                    unsigned long *wmin, unsigned long *wmax) {
    if (depth > 5) return 0;
    DIR *d = opendir(path);
    if (!d) return 0;
    struct dirent *e;
    char p[MAXFNAME * 2];
    while ((e = readdir(d)) && *nf < MAXF) {
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof p, "%s/%s", path, e->d_name);
        struct stat st;
        if (stat(p, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) { scan_dir(p, ef, nf, depth + 1, loaded, wmin, wmax); continue; }
        if (!S_ISREG(st.st_mode)) continue;
        size_t nl = strlen(e->d_name);
        if (nl < 9 || strcmp(e->d_name + nl - 8, ".rhysida") != 0) continue;
        long sz = st.st_size;
        if (sz <= 0x40C || (unsigned long)sz > MAXFILEBYTES) continue;
        if (*loaded + (unsigned long)sz > 2ul * 1024ul * 1024ul * 1024ul) {
            fprintf(stderr, ".. memory cap reached; skipping deeper files\n"); continue;
        }
        FILE *f = fopen(p, "rb");
        if (!f) continue;
        unsigned char *b = (unsigned char *)malloc((size_t)sz);
        if (!b || fread(b, 1, (size_t)sz, f) != (size_t)sz) { if (b) free(b); fclose(f); continue; }
        fclose(f);
        const char *base = p;
        for (const char *q = p; *q; q++) if (*q == '/') base = q + 1;
        snprintf(ef[*nf].name, MAXFNAME, "%s", base);
        ef[*nf].data = b; ef[*nf].sz = sz;
        ef[*nf].plainlen = sz - 0x40C;
        unsigned long mt = (unsigned long)st.st_mtime;
        ef[*nf].mtime = mt;
        if (*wmin == 0 || mt < *wmin) *wmin = mt;
        if (mt > *wmax) *wmax = mt;
        *loaded += (unsigned long)sz;
        (*nf)++;
    }
    closedir(d);
    return 0;
}


/* =====================================================================
 * IONSEC Rhysida ESXi Recovery — public victim-facing build (v2.0.0)
 * =====================================================================
 *   banner + ANSI color | --scan dry-run | confirm gate | report gen
 *   idiot-proof CLI | as-is disclaimer | --about (services)
 * Core recovery logic unchanged from the validated research build:
 *   recursive *.rhysida scan, clock window from file mtimes,
 *   blind seed sweep (RSA-4096-OAEP trailer replay oracle),
 *   AES-256-CTR restore + sha256 report. Inputs never modified.
 * ===================================================================*/
#define _GNU_SOURCE
#define TOOL_VERSION "1.0.0"
#define TOOL_NAME "insito"
#define TOOL_TAGLINE "MIT-licensed open-source Rhysida ESXi (model Rhysida-0.1) recovery - IONSEC.IO"
#define SITE_URL     "https://ionsec.io"
#define REPO_URL     "https://github.com/ionsec/insito"

static const char *SERVICES_ABOUT =
"  WHEN AN INCIDENT STRIKES\n"
"  We go past the visible threat and unravel the entire chain -\n"
"  how they got in, what they touched, and what would let them back.\n"
"  Containment is not the finish line.\n"
"\n"
"  EMERGENCY INCIDENT RESPONSE   24/7 intake, assured 4-hour response,\n"
"                                memory capture, attack-chain reconstruction\n"
"                                and guided recovery.   [IR]\n"
"  TIER-3 AS A SERVICE (T3AAS)   Senior RE, threat hunting and forensic\n"
"                                analysts on demand for your SOC or MSSP.\n"
"  CYBER PREPAREDNESS            Readiness front-loaded before the breach:\n"
"                                visibility, playbooks, rehearsals.\n"
"  RANSOMPROTECT                 Early-chain ransomware and wiper detection\n"
"                                where OS defenses fall short.\n"
"\n"
"    4 hours   assured response from first contact, 24/7\n"  /* line1 */
"    +100k     hours of research and DFIR expertise\n"
"    ~85%%      MTTR reduction achievable with our IR team\n"
"    6         open-source DFIR tools published and maintained\n";

static const char *DISCLAIMER =
"DISCLAIMER / TERMS OF USE\n"
"This tool is provided 'AS IS', without warranty of any kind, express or\n"
"implied, including but not limited to fitness for a particular purpose.\n"
"Use it ONLY on systems you own or are explicitly authorized to operate.\n"
"Recovery of every encrypted file cannot be guaranteed: files encrypted\n"
"with partial coverage, overwritten, truncated or otherwise damaged may\n"
"not be restorable. Always keep the originals until you have verified the\n"
"restored copies. The operator assumes all responsibility for use of this\n"
"tool; IONSEC accepts no liability for data loss, downtime or misuse.\n";

static int USE_COLOR = 0;
static const char *CR_ = "", *CG_ = "", *CY_ = "", *CC_ = "", *CD_ = "", *CB_ = "", *CX_ = "";

/* === MIT license + one-time acceptance (versioned, stamped) ===== */
#define LICENSE_VERSION "1.0"

static const char *LICENSE_NOTICE =
    "INSITO %s :: Rhysida ESXi locker recovery :: license v1.0\n"
    "Copyright 2026 IONSEC.IO. Released under the MIT License; the unmodified\n"
    "license text ships with the binary (see LICENSE).\n"
    "\n"
    "1. Use only on systems you own or are authorized to recover.\n"
    "2. Recovery is best-effort: no guarantee that any file is restored,\n"
    "   intact, or complete.\n"
    "3. AS-IS, NO WARRANTY of any kind. The MIT license text is your\n"
    "   complete statement of terms and remedies.\n"
    "4. Encrypted originals are opened read-only. Keep a backup copy of\n"
    "   them until you have verified the decrypted output.\n"
    "5. Redistribution: MIT terms require the copyright notice and license\n"
    "   text to accompany every copy.\n"
    "\n"
    "Unlawful use is prohibited and not condoned; you alone are responsible\n"
    "for your use. Scripts: --accept-license. Reprint: --license.";

static const char *LICENSE_FULL =
"INSITO - MIT License - (c) 2026 IONSEC.IO\n\n"
"OPERATING NOTICE (binding, in addition to the MIT text):\n"
"  1. Provided AS IS, at your own risk; no liability, no warranty.\n"
"  2. Use only on ESXi hosts/files you own or are authorized to operate.\n"
"  3. Recovery is best-effort; keep encrypted originals until restored\n"
"     copies are verified.\n"
"  4. On redistribution keep the MIT license and this notice.\n\n"
"MIT License\n\n"
"Copyright (c) 2026 IONSEC.IO\n\n"
"Permission is hereby granted, free of charge, to any person obtaining a copy\n"
"of this software and associated documentation files (the \"Software\"), to deal\n"
"in the Software without restriction, including without limitation the rights\n"
"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n"
"copies of the Software, and to permit persons to whom the Software is\n"
"furnished to do so, subject to the following conditions:\n\n"
"The above copyright notice and this permission notice shall be included in all\n"
"copies or substantial portions of the Software.\n\n"
"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n"
"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"
"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n"
"SOFTWARE.\n";

static char STAMP_PATH[600];
static char STAMP_FILE[800];

static void stamp_path_init(void) {
    const char *p = getenv("INSITO_LICENSE_PATH");
    const char *xdg = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");
    if (!home || !*home) home = "/root";
    if (p && *p) snprintf(STAMP_FILE, sizeof STAMP_FILE, "%s", p);
    else if (xdg && *xdg) snprintf(STAMP_FILE, sizeof STAMP_FILE, "%s/insito/acceptance.json", xdg);
    else snprintf(STAMP_FILE, sizeof STAMP_FILE, "%s/.config/insito/acceptance.json", home);
    snprintf(STAMP_PATH, sizeof STAMP_PATH, "%s", STAMP_FILE);
    char *sl = strrchr(STAMP_PATH, '/');
    if (sl) *sl = 0;
}

/* strict checks: regular file, not a symlink, mode 0600 */
static int stamp_perms_ok(void) {
    struct stat lst, st;
    if (lstat(STAMP_FILE, &lst) != 0) return 0;
    if (S_ISLNK(lst.st_mode)) return 0;
    if (stat(STAMP_FILE, &st) != 0) return 0;
    if (!S_ISREG(st.st_mode)) return 0;
    if ((st.st_mode & 07777) != 0600) return 0;
    return 1;
}

/* structural validation of our own writer's JSON */
static int stamp_json_ok(char *buf, size_t bufsz) {
    if (!stamp_perms_ok()) return 0;
    FILE *f = fopen(STAMP_FILE, "r");
    if (!f) return 0;
    size_t got = fread(buf, 1, bufsz - 1, f);
    fclose(f);
    buf[got] = 0;
    if (got < 40 || buf[0] != '{') return 0;
    static const char *keys[] = {
        "\"schema\":\"insito.license.v1\"", "\"eula\":\"", "\"tool_version\":\"",
        "\"accepted_utc\":\"", "\"method\":\"", "\"uid\":\""};
    for (unsigned i = 0; i < sizeof keys / sizeof keys[0]; i++)
        if (!strstr(buf, keys[i])) return 0;
    char *v = strstr(buf, "\"eula\":\"");
    if (!v) return 0;
    v += 8;
    return strncmp(v, LICENSE_VERSION, strlen(LICENSE_VERSION)) == 0;
}

/* 1 = a stamp for the current LICENSE_VERSION exists and is valid */
static int stamp_valid(char *tsbuf, size_t tsz) {
    static char buf[512];
    if (!stamp_json_ok(buf, sizeof buf)) return 0;
    if (tsbuf && tsz) {
        char *t = strstr(buf, "\"accepted_utc\":\"");
        if (t) {
            t += 16;
            size_t L = strcspn(t, "\"");
            snprintf(tsbuf, tsz, "%.*s", (int)L, t);
        }
    }
    return 1;
}

static void stamp_write(const char *how) {
    mkdir(STAMP_PATH, 0700);
    char iso[64];
    struct tm tmv;
    time_t now = time(NULL);
    gmtime_r(&now, &tmv);
    strftime(iso, sizeof iso, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    char sha[80] = "";
    FILE *p = popen("sha256sum /proc/self/exe 2>/dev/null", "r");
    if (p) {
        char ln[128] = {0};
        if (fgets(ln, sizeof ln, p)) snprintf(sha, sizeof sha, "%.64s", ln);
        pclose(p);
    }
    char tmpl[900];
    snprintf(tmpl, sizeof tmpl, "%s.tmp.XXXXXX", STAMP_FILE);
    int fd = mkstemp(tmpl);
    if (fd < 0) return;
    FILE *w = fdopen(fd, "w");
    if (!w) {
        close(fd);
        unlink(tmpl);
        return;
    }
    fprintf(w, "{\"schema\":\"insito.license.v1\",\"eula\":\"%s\","
               "\"tool_version\":\"%s\",\"accepted_utc\":\"%s\","
               "\"method\":\"%s\",\"uid\":\"%d\"",
            LICENSE_VERSION, TOOL_VERSION, iso, how, (int)getuid());
    if (sha[0]) fprintf(w, ",\"binary_sha256\":\"%s\"}", sha);
    else fprintf(w, "}");
    fclose(w);
    chmod(tmpl, 0600);
    if (rename(tmpl, STAMP_FILE) == 0) {
        printf("%s[+]%s license v%s accepted; recorded in %s\n", CG_, CX_, LICENSE_VERSION, STAMP_FILE);
#ifdef LOG_AUTH
        openlog("insito", 0, LOG_AUTH);
        syslog(LOG_AUTH | LOG_NOTICE, "INSITO: license v%s accepted (tool %s, method=%s, uid=%d)",
               LICENSE_VERSION, TOOL_VERSION, how, (int)getuid());
        closelog();
#endif
    } else {
        unlink(tmpl);
    }
}

/* --license-status */
static void print_license_status(void) {
    stamp_path_init();
    char ts[160] = {0};
    if (stamp_valid(ts, sizeof ts)) {
        printf("path=%s\neula=%s\naccepted_utc=%s\ntool_version=%s\n",
               STAMP_FILE, LICENSE_VERSION, ts, TOOL_VERSION);
        static char buf[512];
        FILE *f = fopen(STAMP_FILE, "r");
        if (f) {
            size_t g = fread(buf, 1, sizeof buf - 1, f);
            fclose(f);
            buf[g] = 0;
            char *mm = strstr(buf, "\"method\":\"");
            char *uu = strstr(buf, "\"uid\":\"");
            if (mm) { mm += 10; size_t L = strcspn(mm, "\""); printf("method=%.*s\n", (int)L, mm); }
            if (uu) { uu += 7; size_t L2 = strcspn(uu, "\""); printf("uid=%.*s\n", (int)L2, uu); }
        }
        exit(0);
    }
    printf("path=%s\nstatus=not-accepted\n", STAMP_FILE);
    exit(1);
}

/* ----------------------------- UI layer ---------------------------- */


static void color_init(int force_off) {
    USE_COLOR = isatty(STDOUT_FILENO) && !force_off && !getenv("NO_COLOR");
    if (USE_COLOR) {
        CR_ = "\x1b[1;31m"; CG_ = "\x1b[1;32m"; CY_ = "\x1b[1;33m";
        CC_ = "\x1b[1;36m"; CD_ = "\x1b[2m";   CB_ = "\x1b[1m"; CX_ = "\x1b[0m";
    }
}


/* ---- one-time license gate --------------------------------------- */
static int license_gate(int accept_now) {
    stamp_path_init();
    char ts[160] = {0};
    if (!accept_now && stamp_valid(ts, sizeof ts)) {
        printf("[+] license v%s ok (%s)\n", LICENSE_VERSION, ts);
        return 1;
    }
    if (accept_now) {
        stamp_write("flag");
        return 1;
    }
    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr,
            "[insito] license v%s not yet accepted, non-interactive run "
            "(use --accept-license or --license)\n", LICENSE_VERSION);
        return 0;
    }
    printf(LICENSE_NOTICE, TOOL_VERSION);
    printf("\nType \"accept\" to accept and continue, anything else to cancel.\n> ");
    fflush(stdout);
    char ans[64] = {0};
    int empties = 0;
    for (;;) {
        if (!fgets(ans, sizeof ans, stdin)) { printf("\ncancelled.\n"); return 0; }
        size_t L = strlen(ans);
        while (L && (ans[L-1] == '\n' || ans[L-1] == '\r' || ans[L-1] == ' ')) ans[--L] = 0;
        if (L == 0) {
            if (++empties >= 2) { printf("cancelled (empty input).\n"); return 0; }
            printf("> ");
            fflush(stdout);
            continue;
        }
        for (char *p = ans; *p; p++) if (*p >= 'A' && *p <= 'Z') *p = (char)(*p + 32);
        break;
    }
    if (strcmp(ans, "accept") != 0) {
        printf("not accepted - nothing was read, nothing was written.\n");
        return 0;
    }
    stamp_write("prompt");
    return 1;
}

static void banner(void) {
    printf("%s", CB_);
    " ___ _   _ ____ ___ _____ ___  \n"
    "|_ _| \\ | / ___|_ _|_   _/ _ \\ \n"
    " | ||  \\| \\___ \\| |  | || | | |\n"
    " | || |\\  |___) | |  | || |_| |\n"
    "|___|_| \\_|____/___| |_| \\___/ \n"
    "                               \n";
    printf("%s", CX_);
    printf("%s  INSITO%s\n", CR_, CX_);
    printf("  %s\n", TOOL_TAGLINE);
    printf("  build %s%s%s \xc2\xb7 MIT \xc2\xb7 %s%s%s\n\n",
           CB_, TOOL_VERSION, CX_, CC_, REPO_URL, CX_);
}

static void first_run_notice(void) {
    printf("%s%s%s", CD_, DISCLAIMER, CX_);
    printf("\n  %s--about%s to see who we are   ·   %s--help%s for usage   ·   "
           "%s--scan%s to preview safely\n\n", CB_, CX_, CB_, CX_, CB_, CX_);
}

static void usage_full(const char *argv0) {
    printf("%sUSAGE%s\n", CB_, CX_);
    printf("  %s --datastore <path>               recover *.rhysida under <path>\n", argv0);
    printf("  %s --scan <path>                   dry-run: show what WOULD happen, decrypt nothing\n", argv0);
    printf("\n%sOPTIONS%s\n", CB_, CX_);
    printf("  --datastore <dir|file>   target: a directory tree or one *.rhysida file\n");
    printf("  --out <dir>              restore dir (default: <datastore>/rhysida_recovered)\n");
    printf("  --key <locker-sample>    auto-carve the campaign public key from a preserved\n"
           "                           locker binary (for rotated-key builds of the strain)\n");
    printf("  --window <seconds>       clock window around file mtimes (default 600)\n");
    printf("  --offline                 search the calendar range around now (no mtimes needed)\n");
    printf("  --threads <n>             cap offline sweep workers (default: all cores,\n");
    printf("                            memory-guarded, max 128)\n");
    printf("  --lookback <days>         how far back --offline searches (default 30)\n");
    printf("  --no-offline              never fall back to the automatic offline search\n");
    printf("  --clock <epoch>           center the clock window here instead of mtimes\n"
               "                           (for files copied without timestamps)\n");
    printf("  --scan <path>            preview: files, window, time estimate — no changes\n");
    printf("  --accept-license         accept once, non-interactively (recorded + silent after)\n");
    printf("  --license                print the MIT license + operating notice\n");
    printf("  --license-status         print acceptance stamp status (exit 1 if absent)\n");
    printf("  --yes                    skip the confirmation prompt (for scripts)\n");
    printf("  --keep-keys              additionally write per-file AES key/iv material where\n"
           "                           recovered (analyst option)\n");
    printf("  --no-color               disable ANSI colors (NO_COLOR is also honored)\n");
    printf("  --about                  who we are — services, response, research\n");
    printf("  -h | --help              this page\n");
    printf("  --version                print build version\n");
    printf("\n%sQUICKSTART%s\n", CB_, CX_);
    printf("  1. %s./tool --scan /vmfs/volumes/datastore1%s        %s# look first%s\n", CB_, CX_, CD_, CX_);
    printf("  2. %s./tool --datastore /vmfs/volumes/datastore1%s   %s# decrypt, originals untouched%s\n", CB_, CX_, CD_, CX_);
    printf("  3. report + sha256 of every restored file lands in rhysida_recovered/\n");
    printf("\n%s", DISCLAIMER);
    printf("\n  License (MIT) + operating notice: run with %s--license%s.\n", CB_, CX_);
    printf("\n  Emergency response around the clock: %s%s/services/emergency-ir%s · info@ionsec.io\n",
           CC_, SITE_URL, CX_);
}

static void about_screen(void) {
    banner();
    printf("%s", CY_);
    fputs(SERVICES_ABOUT, stdout);
    printf("%s", CX_);
    printf("  Tools & research, free to read: %s%s/tooling%s\n", CC_, SITE_URL, CX_);
    printf("  Knowledge base:                 %s%s/resources%s\n", CC_, SITE_URL, CX_);
    printf("  Emergency contact:              %sinfo@ionsec.io%s\n\n", CB_, CX_);
    printf("\n  Full license: %s--license%s  |  repo: %s%s%s\n\n", CB_, CX_, CC_, REPO_URL, CX_);
}

static const char *fmt_est(double s) {
    static char buf[64];
    if (s < 90)         snprintf(buf, sizeof buf, "~%.0f s",  s);
    else if (s < 5400)  snprintf(buf, sizeof buf, "~%.0f min", s / 60.0);
    else                snprintf(buf, sizeof buf, "~%.1f h",  s / 3600.0);
    return buf;
}

/* ------------------------- report generator ------------------------ */
static void json_escape(FILE *f, const char *s) {
    for (; *s; s++) if (*s == '"' || *s == '\\') fprintf(f, "\\%c", *s); else fputc(*s, f);
}

static void write_report(const char *outdir, const char *store, const char *out,
                         EF *ef, int nf, int restored, uint32_t lo, uint32_t hi,
                         uint32_t seed, double wall, int hit_ok, const char *keymode,
                         const char *eula_mode_txt, const char *eula_ver) {
    char iso[64], base[64], pf[512], pj[512];
    struct tm tmv; time_t now = time(NULL);
    gmtime_r(&now, &tmv);
    strftime(iso, sizeof iso, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    strftime(base, sizeof base, "recovery-report-%Y%m%d-%H%M%S", &tmv);
    snprintf(pf, sizeof pf, "%s/%s.txt",  outdir, base);
    snprintf(pj, sizeof pj, "%s/%s.json", outdir, base);

    struct utsname u;
    uname(&u);

    FILE *f = fopen(pf, "w");
    if (f) {
        fprintf(f, "IONSEC RHYSIDA ESXi RECOVERY REPORT\n");
        fprintf(f, "=====================================\n");
        fprintf(f, "generated : %s\n", iso);
        fprintf(f, "tool      : rhysida-esxi-decryptor %s (key: %s)\n", TOOL_VERSION, keymode);
        fprintf(f, "host      : %s %s %s\n", u.sysname, u.nodename, u.release);
        fprintf(f, "datastore : %s\n", store);
        fprintf(f, "restored  : %d/%d files into %s\n", restored, nf, out);
        fprintf(f, "clock     : window [%lu..%lu] -> encryption clock %u (hit %s)\n",
                (unsigned long)lo, (unsigned long)hi, (unsigned)seed, hit_ok ? "confirmed" : "PARTIAL");
        fprintf(f, "license   : v%s accepted (%s)\n", eula_ver, eula_mode_txt);
        fprintf(f, "duration  : %.1f s\n\n", wall);
        fprintf(f, "PER-FILE RESULTS\n----------------\n");
        for (int i = 0; i < nf; i++) {
            if (!ef[i].found || !ef[i].data) {
                fprintf(f, "[not-match] %s (outside the recovered stream)\n", ef[i].name);
                continue;
            }
            unsigned char dh[32]; unsigned long hl = 32;
            hash_memory(find_hash("sha256"), ef[i].data, (unsigned long)ef[i].sz, dh, &hl);
            char chex[65]; for (int q = 0; q < 32; q++) sprintf(chex + q * 2, "%02x", dh[q]);
            fprintf(f, "[seq %d] %s -> %s/<original name>\n"
                       "        sha256(ciphertext)=%s\n"
                       "        verify restored copies against your backups before removing originals\n",
                    ef[i].hit_seq, ef[i].name, out, chex);
        }
        fprintf(f, "\nNEXT STEPS\n----------\n");
        fprintf(f, "- keep the encrypted originals until restored copies are verified\n");
        fprintf(f, "- files listed [not-match] were not part of the recovered stream:\n");
        fprintf(f, "  retry with a wider --window, or pass --key with a preserved locker sample\n");
        fprintf(f, "- keep this report (and the .json) for your insurers and IR documentation\n");
        fprintf(f, "\n%s", DISCLAIMER);
        fprintf(f, "\n24/7 emergency response: %s/services/emergency-ir | info@ionsec.io\n\n", SITE_URL);
        fclose(f);
        printf("%s[+] report%s written: %s\n", CG_, CX_, pf);
    }
    f = fopen(pj, "w");
    if (f) {
        fprintf(f, "{\n  \"tool\": \"rhysida-esxi-decryptor\",\n  \"version\": \"%s\",\n", TOOL_VERSION);
        fprintf(f, "  \"generated\": \"%s\",\n  \"key_mode\": \"%s\",\n", iso, keymode);
        fprintf(f, "  \"host\": {\"sysname\": \"%s\", \"nodename\": \"%s\", \"release\": \"%s\"},\n",
                u.sysname, u.nodename, u.release);
        fprintf(f, "  \"datastore\": \"");
        json_escape(f, store);
        fprintf(f, "\",\n  \"out\": \"");
        json_escape(f, out);
        fprintf(f, "\",\n  \"window\": [%lu, %lu],\n  \"clock\": %u,\n  \"hit\": %s,\n  \"duration_sec\": %.1f,\n",
                (unsigned long)lo, (unsigned long)hi, (unsigned)seed, hit_ok ? "true" : "false", wall);
        fprintf(f, "  \"license\": {\"version\": \"%s\", \"accepted\": true, \"mode\": \"%s\"},\n",
                eula_ver, eula_mode_txt);
        fprintf(f, "  \"files\": [\n");
        for (int i = 0; i < nf; i++) {
            if (!ef[i].found || !ef[i].data) {
                fprintf(f, "    {\"name\": \"");
                json_escape(f, ef[i].name);
                fprintf(f, "\", \"state\": \"not-matched\"}%s\n", i + 1 < nf ? "," : "");
                continue;
            }
            unsigned char dh[32]; unsigned long hl = 32;
            hash_memory(find_hash("sha256"), ef[i].data, (unsigned long)ef[i].sz, dh, &hl);
            char chex[65]; for (int q = 0; q < 32; q++) sprintf(chex + q * 2, "%02x", dh[q]);
            fprintf(f, "    {\"name\": \"");
            json_escape(f, ef[i].name);
            fprintf(f, "\", \"state\": \"restored\", \"seq\": %d, \"sha256_ct\": \"%s\"}%s\n",
                    ef[i].hit_seq, chex, i + 1 < nf ? "," : "");
        }
        fprintf(f, "  ]\n}\n");
        fclose(f);
        printf("%s[+] json report%s   : %s\n", CG_, CX_, pj);
    }
}

/* ------------------------------ main ------------------------------- */
/* ================================================================== *
 * OFFLINE fallback sweep: no timestamp anchor required               *
 * Searches the calendar range around "now" (or a caller-bound end)   *
 * across all CPU cores; first full trailer match wins.               *
 * ================================================================== */
#include <pthread.h>

static volatile int ob_stop = 0;          /* 1 = someone hit or user died */
static unsigned long long ob_next = 0;    /* atomic candidate cursor      */
static unsigned long long ob_done = 0;    /* atomic progress counter      */
static uint32_t ob_hit = 0;               /* winning clock                */
static int ob_hitres = 0;
static uint32_t ob_lo = 0, ob_hi = 0;
static pthread_mutex_t ob_print = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    EF lef[MAXF];          /* thread-private found/hit_seq flags        */
    EF *src;               /* shared read-only data                     */
    int nf;
    int prng_idx, hash_idx;
    rsa_key *pub;
    uint32_t lo, hi;
    int seqcap;
    int tid;
} OB;

static void *ob_worker(void *arg) {
    OB *w = (OB *)arg;
    EF *le = w->lef;
    for (int i = 0; i < w->nf; i++) {
        le[i] = w->src[i];
        le[i].found = 0;
    }
    for (;;) {
        if (ob_stop) break;
        unsigned long long idx = __atomic_fetch_add(&ob_next, 1, __ATOMIC_RELAXED);
        if (w->lo + (uint32_t)idx > w->hi) break;
        uint32_t seed = w->lo + (uint32_t)idx;
        for (int i = 0; i < w->nf; i++) le[i].found = 0;
        int res = sweep_seed(seed, w->prng_idx, w->hash_idx, w->pub, le, w->nf, w->seqcap);
        __atomic_fetch_add(&ob_done, 1, __ATOMIC_RELAXED);
        if (res > 0 && !ob_stop) {
            pthread_mutex_lock(&ob_print);
            if (!ob_stop) {                       /* first writer owns it */
                ob_hit = seed;
                ob_hitres = res;
                for (int i = 0; i < w->nf; i++) w->src[i].found = le[i].found;
                ob_stop = 1;
                printf("%s[#HIT]%s encryption clock = %s%u%s - %d/%d files matched (offline)\n",
                       CR_, CX_, CB_, (unsigned)seed, CX_, res, w->nf);
                fflush(stdout);
            }
            pthread_mutex_unlock(&ob_print);
            break;
        }
    }
    return NULL;
}

static void *ob_monitor(void *arg) {
    (void)arg;
    unsigned long long total = (unsigned long long)(ob_hi >= ob_lo ? (ob_hi - ob_lo) : 0) + 1;
    unsigned long long prev = 0;
    struct timespec ts0, tsk;
    clock_gettime(CLOCK_MONOTONIC, &ts0);
    struct timespec slp = {2, 0};
    for (;;) {
        nanosleep(&slp, NULL);
        if (ob_stop) break;
        unsigned long long d = __atomic_load_n(&ob_done, __ATOMIC_RELAXED);
        unsigned long long n = __atomic_load_n(&ob_next, __ATOMIC_RELAXED);
        clock_gettime(CLOCK_MONOTONIC, &tsk);
        double el = (double)(tsk.tv_sec - ts0.tv_sec) + (double)(tsk.tv_nsec - ts0.tv_nsec) / 1e9;
        double rate = (el > 0.5) ? (double)(d - 0) / el : 0.0;
        double remain = (rate > 0.01) ? (double)(total - n) / rate : 0.0;
        char *eta = fmt_est(remain);
        pthread_mutex_lock(&ob_print);
        printf("%s[.. offline%s %llu/%llu candidates  ~%.0f c/s  ETA %s%s\n",
               CD_, CX_, n, total, rate, eta, CX_);
        pthread_mutex_unlock(&ob_print);
        fflush(stdout);
        prev = d;
    }
    return NULL;
}

/* runs the offline fallback; returns >0 (hit) or 0 (nothing found).
 * lookback_secs bounds the search [end - lookback .. end]. */
static int threads_override = 0;   /* 0 = auto (cores, memory-guarded) */

static int offline_threads_hint(void) {
    long c = sysconf(_SC_NPROCESSORS_ONLN);
    if (c < 1) c = 1;
    if (threads_override > 0) { c = threads_override; if (c > 1024) c = 1024; return (int)c; }
    return (c > 128) ? 128 : (int)c;
}

static int offline_sweep(EF *ef, int nf, int prng_idx, int HASH_IDX, rsa_key *pub,
                         uint32_t end, unsigned long lookback_secs, int seqcap,
                         uint32_t *out_lo, uint32_t *out_hi, unsigned long *nthreads) {
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 1;
    int T = (cores > 128) ? 128 : (int)cores;
    /* memory guard: each worker holds a thread-private EF table (sharable
     * pointer fields) plus its own PRNG/RSA buffers; budget ~16 MB RSS each */
    long avail_kb = 0;
    FILE *mf = fopen("/proc/meminfo", "r");
    if (mf) {
        char lnb[160];
        while (fgets(lnb, sizeof lnb, mf))
            if (sscanf(lnb, "MemAvailable: %ld kB", &avail_kb) == 1) break;
        fclose(mf);
    }
    int T_mem = 0;
    if (avail_kb > 0) {
        T_mem = (int)((long long)avail_kb * 1024 / (long long)(16LL * 1024 * 1024));
        if (T_mem < 1) T_mem = 1;
        if (T > T_mem) T = T_mem;
    }
    if (threads_override > 0) T = (threads_override > 1024) ? 1024 : threads_override;
    if (T < 1) T = 1;
    uint32_t lo32 = (uint32_t)((long long)end - (long long)lookback_secs);
    uint32_t hi32 = end;
    ob_stop = 0; ob_next = 0; ob_done = 0; ob_hit = 0; ob_hitres = 0;
    ob_lo = lo32; ob_hi = hi32;
    printf("%s[+] offline search%s: %u .. %u (%llu candidates, %d threads, est %s)\n",
           CB_, CX_, (unsigned)lo32, (unsigned)hi32,
           (unsigned long long)(hi32 - lo32) + 1, T, fmt_est((double)(hi32 - lo32) * 0.045 * nf / T));
    printf("    hardware: %ld core%s%s%lg GB RAM available -> %d worker thread%s\n",
           cores, (cores == 1) ? "" : "s", avail_kb > 0 ? ", " : ", n/a ", avail_kb > 0 ? (double)avail_kb / 1048576.0 : 0.0,
           T, (T == 1) ? "" : "s");
    fflush(stdout);
    pthread_t mon;
    pthread_create(&mon, NULL, ob_monitor, NULL);
    pthread_t th[128];
    OB *jobs = (OB *)malloc(sizeof(OB) * (size_t)T);
    if (!jobs) { ob_stop = 1; pthread_join(mon, NULL); return 0; }
    int started = 0;
    for (int t = 0; t < T; t++) {
        jobs[t].src = ef; jobs[t].nf = nf; jobs[t].prng_idx = prng_idx;
        jobs[t].hash_idx = HASH_IDX; jobs[t].pub = pub;
        jobs[t].lo = lo32; jobs[t].hi = hi32; jobs[t].seqcap = seqcap; jobs[t].tid = t;
        if (pthread_create(&th[t], NULL, ob_worker, &jobs[t]) == 0) started++;
        else break;
    }
    for (int t = 0; t < started; t++) pthread_join(th[t], NULL);
    ob_stop = 1;
    pthread_join(mon, NULL);
    free(jobs);
    printf("\n");
    if (nthreads) *nthreads = (unsigned long)started;
    if (ob_hitres > 0) {
        if (out_lo) *out_lo = (uint32_t)(ob_hit > lookback_secs ? ob_hit - (uint32_t)lookback_secs : 0);
        if (out_hi) *out_hi = (uint32_t)ob_hi;
        return ob_hitres;
    }
    return 0;
}


int main(int argc, char **argv) {
    const char *store = NULL, *outdir = NULL, *keyfile = NULL;
    const char *scanpath = NULL;
    unsigned long window = 600;
    unsigned long forced = 0;  /* --clock: operator-provided detonation epoch */
    int offline_now = 0, no_offline = 0;
    unsigned long lookback_days = 30;
    unsigned long off_until = 0;
    int keep_keys = 0, yes = 0, no_color = 0, accept_license = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--datastore") && i + 1 < argc) store = argv[++i];
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) outdir = argv[++i];
        else if (!strcmp(argv[i], "--key") && i + 1 < argc) keyfile = argv[++i];
        else if (!strcmp(argv[i], "--offline")) { offline_now = 1; continue; }
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) {
            if (argv[i+1][0] < '0' || argv[i+1][0] > '9') { fprintf(stderr, "[x] --threads needs a number\n"); return 1; }
            threads_override = (int)strtoul(argv[i+1], NULL, 10);
            if (threads_override < 1 || threads_override > 1024) { fprintf(stderr, "[x] --threads 1..1024\n"); return 1; }
            i++;
            continue;
        }
        else if (!strcmp(argv[i], "--no-offline")) { no_offline = 1; continue; }
        else if (!strcmp(argv[i], "--lookback") && i + 1 < argc) {
            if (argv[i+1][0] < '0' || argv[i+1][0] > '9') { fprintf(stderr, "[x] --lookback needs a number of days\n"); return 1; }
            lookback_days = (unsigned long)strtoul(argv[i+1], NULL, 10);
            if (lookback_days == 0 || lookback_days > 366) { fprintf(stderr, "[x] --lookback in days, 1..366\n"); return 1; }
            i++;
            continue;
        }
        else if (i + 1 < argc && !strcmp(argv[i], "--offline-until")) {   /* testing knob */
            off_until = (unsigned long)strtoul(argv[i+1], NULL, 10);
            i++;
            continue;
        }
        else if (!strcmp(argv[i], "--clock") && i + 1 < argc) {
            if (argv[i+1][0] < '0' || argv[i+1][0] > '9') { fprintf(stderr, "[x] --clock needs numeric epoch seconds\n"); return 1; }
            forced = (unsigned long)strtoul(argv[i+1], NULL, 10);
            if (forced < 1000000000ul) { fprintf(stderr, "[x] --clock looks implausible (expect unix epoch seconds)\n"); return 1; }
            i++;
            continue;
        } else if (!strcmp(argv[i], "--window") && i + 1 < argc) {
            window = strtoul(argv[++i], 0, 10);
            if (window < 30 || window > 86400) {
                fprintf(stderr, "%s[x] --window must be between 30 and 86400 seconds%s\n", CR_, CX_);
                fprintf(stderr, "    hint: the default 600 covers the locker's pre-encryption lag\n");
                return 1;
            }
        }
        else if (!strcmp(argv[i], "--scan") && i + 1 < argc) scanpath = argv[++i];
        else if (!strcmp(argv[i], "--keep-keys")) keep_keys = 1;
        else if (!strcmp(argv[i], "--yes")) yes = 1;
        else if (!strcmp(argv[i], "--no-color")) no_color = 1;
        else if (!strcmp(argv[i], "--version")) { printf("insito %s\n", TOOL_VERSION); return 0; }
        else if (!strcmp(argv[i], "--about")) { color_init(0); about_screen(); return 0; }
        else if (!strcmp(argv[i], "--license")) { color_init(no_color); fputs(LICENSE_FULL, stdout); return 0; }
        else if (!strcmp(argv[i], "--license-status") || !strcmp(argv[i], "--eula-status")) { color_init(no_color); print_license_status(); }
        else if (!strcmp(argv[i], "--accept-license")) accept_license = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { color_init(0); banner(); usage_full(argv[0]); return 0; }
        else {
            color_init(no_color);
            fprintf(stderr, "%s[x] unknown option: %s%s\n\n", CR_, argv[i], CX_);
            banner(); usage_full(argv[0]);
            return 1;
        }
    }

    color_init(no_color);

    /* license gate — every real run (scan or decrypt) requires acceptance */
    int license_mode = 0;
    if (scanpath || store) {
        license_mode = license_gate(accept_license);
        if (!license_mode) return 2;  /* gate refusal per spec */
    }

    /* syntax checks ------------------------------------------------- */
    struct stat st0;
    if (!scanpath && !store) {
        if (isatty(STDIN_FILENO)) {
            first_run_notice();
            fprintf(stderr, "%s[!] no target given%s\n\n", CY_, CX_);
            fprintf(stderr, "    you probably want one of these:\n");
            fprintf(stderr, "      %s%s --scan <datastore>%s             %s# preview safely%s\n",
                    CB_, TOOL_NAME, CX_, CD_, CX_);
            fprintf(stderr, "      %s%s --datastore <datastore>%s        %s# recover files%s\n",
                    CB_, TOOL_NAME, CX_, CD_, CX_);
            fprintf(stderr, "      %s%s --help%s                        %s# full usage%s\n\n",
                    CB_, TOOL_NAME, CX_, CD_, CX_);
            fprintf(stderr, "    nothing is read or written until you point it at a target.\n");
        } else {
            fprintf(stderr, "no target given. usage: insito --datastore <path>\n");
        }
        return 2;
    }
    const char *target = scanpath ? scanpath : store;
    if (!target || stat(target, &st0) != 0) {
        fprintf(stderr, "%s[x] target path does not exist%s: %s\n", CR_, CX_, target ? target : "(null)");
        fprintf(stderr, "    hint: give the full path, e.g. --datastore /vmfs/volumes/datastore1\n");
        return 1;
    }
    int single_file = S_ISREG(st0.st_mode);
    if (!single_file && !S_ISDIR(st0.st_mode)) {
        fprintf(stderr, "%s[x] target is neither a directory nor a regular file%s: %s\n", CR_, CX_, target);
        return 1;
    }

    /* crypto init (unchanged core) ----------------------------------- */
    ltc_mp = ltm_desc;
    register_cipher(&aes_desc);
    register_hash(&chc_desc);
    register_hash(&sha256_desc);
    register_prng(&chacha20_prng_desc);
    int CIPHER = find_cipher("aes");
    chc_register(CIPHER);
    int HASH_IDX = find_hash("chc_hash");
    int PRNG_IDX = find_prng("chacha20");

    unsigned char E[3] = {0x01, 0x00, 0x01};
    rsa_key pub;
    const char *keymode = "embedded strain key (known-2026-11 campaign)";
    if (keyfile) {
        FILE *kf = fopen(keyfile, "rb");
        if (!kf) {
            fprintf(stderr, "%s[x] cannot open --key file%s: %s\n", CR_, CX_, keyfile);
            return 2;
        }
        fseek(kf, 0, SEEK_END); long klen = ftell(kf); fseek(kf, 0, SEEK_SET);
        if (klen <= 0 || klen > (long)(512 * 1024 * 1024)) {
            fprintf(stderr, "%s[x] --key file has implausible size%s: %ld\n", CR_, CX_, klen);
            fclose(kf); return 2;
        }
        uint8_t *kb = (uint8_t *)malloc((size_t)klen);
        if (!kb || fread(kb, 1, (size_t)klen, kf) != (size_t)klen) {
            fprintf(stderr, "%s[x] cannot read --key file%s\n", CR_, CX_); fclose(kf); return 2;
        }
        fclose(kf);
        unsigned long at = 0;
        int cr = carve_spki_from(kb, (size_t)klen, &pub, &at);
        if (cr != 0) cr = carve_from_pem(kb, (size_t)klen, &pub, &at);
        if (cr != 0) cr = carve_raw_from(kb, (size_t)klen, &pub, &at);
        if (cr != 0) {
            fprintf(stderr, "%s[x] no RSA-4096 campaign key found in %s%s\n", CR_, CX_, keyfile);
            fprintf(stderr, "    hint: pass the locker binary (.elf), a PEM block (ransom note),\n"
                            "    or a raw modulus+exponent pair - PEM/DER/raw are all accepted.\n");
            return 1;
        }
        unsigned char kh[32]; unsigned long hl = 32;
        hash_memory(find_hash("sha256"), kb + at, 40, kh, &hl);
        char khx[65]; for (int q = 0; q < 32; q++) sprintf(khx + q * 2, "%02x", kh[q]);
        printf("%s[+] carved campaign public key%s from %s at offset 0x%lx (key id %s%.16s…%s)\n",
               CG_, CX_, keyfile, at, CB_, khx, CX_);
        fflush(stdout);
        free(kb);
        keymode = "carved from user-supplied locker sample";
    } else {
        rsa_set_key((unsigned char *)RHYSIDA_N, RHYSIDA_NLEN, E, 3, NULL, 0, &pub);
    }

    /* scan ----------------------------------------------------------- */
    EF *ef = (EF *)calloc(MAXF, sizeof(EF));
    int nf = 0; unsigned long loaded = 0, wmin = 0, wmax = 0;
    char od2[MAXFNAME + 32];
    if (single_file) {
        FILE *fp = fopen(target, "rb");
        if (!fp) { fprintf(stderr, "%s[x] cannot read %s%s\n", CR_, CX_, target); return 2; }
        fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
        unsigned char *b = (unsigned char *)malloc((size_t)sz);
        if (!b || fread(b, 1, (size_t)sz, fp) != (size_t)sz) {
            fprintf(stderr, "%s[x] read failed%s\n", CR_, CX_); fclose(fp); return 2;
        }
        fclose(fp);
        const char *base = target;
        for (const char *q = target; *q; q++) if (*q == '/') base = q + 1;
        snprintf(ef[0].name, MAXFNAME, "%s", base);
        ef[0].data = b; ef[0].sz = sz; ef[0].plainlen = sz - 0x40C;
        wmin = (unsigned long)st0.st_mtime;
        wmax = wmin;
        nf = 1;
        if (!outdir) outdir = "/tmp/recovered";
    } else {
        scan_dir(target, ef, &nf, 0, &loaded, &wmin, &wmax);
        snprintf(od2, sizeof od2, "%s/rhysida_recovered", target);
        if (!outdir) outdir = od2;
    }
    if (nf == 0) {
        printf("%s[?] no *.rhysida files found%s under %s\n\n", CY_, CX_, target);
        first_run_notice();
        return 0;
    }

    uint32_t lo, hi;
    if (offline_now) {
        time_t endt = off_until ? (time_t)off_until : time(NULL) + 60;
        long looksec = (long)lookback_days * 24L * 3600L;
        lo = (uint32_t)((long long)endt - (long long)looksec);
        hi = (uint32_t)endt;
    } else if (forced) {
        lo = (uint32_t)((long)forced - (long)window);
        hi = (uint32_t)((long)forced + (long)window);
    } else {
        lo = (uint32_t)((long)wmin - (long)window);
        hi = (uint32_t)((long)wmax + (long)window);
    }
    unsigned long cands = (unsigned long)(hi - lo + 1);
    double per_cand = 0.055 * (double)nf;              /* measured: ~0.05 s/candidate/file */
    double est = (double)cands * per_cand;
    if (offline_now) {
        long Tc = sysconf(_SC_NPROCESSORS_ONLN);
        if (threads_override > 0) Tc = threads_override;
        if (Tc < 1) Tc = 1;
        est /= (double)Tc;
    }

    /* plan ----------------------------------------------------------- */
    banner();
    printf("%s[plan]%s target        %s\n", CB_, CX_, target);
    printf("%s[plan]%s files         %d encrypted (*.rhysida), %lu.%.1lu MiB\n",
           CB_, CX_, nf, loaded >> 20, ((loaded & 0xFFFFF) * 10) >> 20);
    printf("%s[plan]%s clock window  [%u .. %u]  (%lu candidates, %s)\n",
           CB_, CX_, (unsigned)lo, (unsigned)hi, cands,
           offline_now ? "--offline" : (forced ? "--clock" : "mtime-derived"));
    printf("%s[plan]%s key           %s\n", CB_, CX_, keymode);
    printf("%s[plan]%s est. sweep    %s   (early-break lands sooner; the hit stops it)\n",
           CB_, CX_, fmt_est(est));
    printf("%s[plan]%s output        %s %s(originals never modified)%s\n",
           CB_, CX_, outdir, CD_, CX_);
    if (scanpath) {
        printf("\n%s[scan] dry-run only — nothing written, nothing decrypted%s\n", CG_, CX_);
        printf("  when ready: %s%s --datastore %s%s\n", CB_, TOOL_NAME, target, CX_);
        return 0;
    }

    /* confirm gate --------------------------------------------------- */
    if (!yes && isatty(STDIN_FILENO)) {
        printf("\n  %sProceed with recovery?%s [y/N] ", CB_, CX_);
        fflush(stdout);
        char ans[16] = {0};
        if (!fgets(ans, sizeof ans, stdin) || (ans[0] != 'y' && ans[0] != 'Y')) {
            printf("aborted — nothing was touched.\n");
            return 0;
        }
    } else if (!yes && !isatty(STDIN_FILENO)) {
        fprintf(stderr, "%s[x] non-interactive session and no --yes%s — refusing to start.\n"
                        "    re-run with --yes to skip the confirmation prompt.\n", CR_, CX_);
        return 2;
    }

    /* sweep ----------------------------------------------------------- */
    struct timespec tsa, tsb;
    clock_gettime(CLOCK_MONOTONIC, &tsa);
    uint32_t best_seed = lo; int best_res = -1;
    if (offline_now) {
        uint32_t olo = 0, ohi = 0; unsigned long T = 0;
        best_res = offline_sweep(ef, nf, PRNG_IDX, HASH_IDX, &pub,
                                 (uint32_t)((off_until ? (time_t)off_until : time(NULL)) + 60),
                                 lookback_days * 24ul * 3600ul, SWEEP_SEQS, &olo, &ohi, &T);
        if (best_res > 0) {
            best_seed = ob_hit;
            lo = olo;
            hi = ohi;
        }
    } else {
    uint32_t sw_n = 0;
    printf("\n%s[+] sweeping the encryption clock%s — one RSA replay per candidate per file…\n", CB_, CX_);
    for (uint32_t seed = lo; ; seed++) {
        if (seed > hi) break;
        for (int i = 0; i < nf; i++) ef[i].found = 0;
        int res = sweep_seed(seed, PRNG_IDX, HASH_IDX, &pub, ef, nf, SWEEP_SEQS);
        sw_n++;
        if (sw_n % 16 == 0 || seed == lo) {
            printf("%s[.. sweep%s %u/%lu candidates (best %u → %d/%d files)%s\n",
                   CD_, CX_, (unsigned)(seed - lo + 1), cands,
                   (unsigned)best_seed, best_res, nf, CX_);
            fflush(stdout);
        }
        if (res > best_res) {
            best_res = res; best_seed = seed;
            if (res > 0)
                printf("%s[#HIT]%s encryption clock = %s%u%s — %d/%d files matched\n",
                       CR_, CX_, CB_, (unsigned)seed, CX_, res, nf);
            fflush(stdout);
        }
        if (best_res == nf) break;
    }
    }
    clock_gettime(CLOCK_MONOTONIC, &tsb);    clock_gettime(CLOCK_MONOTONIC, &tsb);
    double wall = (double)(tsb.tv_sec - tsa.tv_sec) + (double)(tsb.tv_nsec - tsa.tv_nsec) / 1e9;

    if (best_res <= 0) {
        printf("\n%s[x] no clock in this window produced the correct wrapping.%s\n\n", CR_, CX_);
        if (!no_offline && !offline_now) {
            /* ---- automatic offline fallback -------------------------------- */
            time_t endt = off_until ? (time_t)off_until : time(NULL) + 60;  /* test knob honored */
            uint32_t olo = 0, ohi = 0; unsigned long T = 0;
            printf("%s[i] no timestamp anchor that fits - launching automatic offline search%s\n"
           "    (%d threads on this machine; may take a while - Ctrl-C to stop;\n"
           "     narrow it with --lookback <days>)\n\n", CB_, CX_, offline_threads_hint());
            fflush(stdout);
            int ores = offline_sweep(ef, nf, PRNG_IDX, HASH_IDX, &pub, (uint32_t)endt,
                                     lookback_days * 24ul * 3600ul, SWEEP_SEQS, &olo, &ohi, &T);
            if (ores > 0) {
                best_res = ores; best_seed = ob_hit;
                lo = olo; hi = ohi;
                goto clock_recovered;
            }
            printf("%s[x] offline search found nothing in the last %lu days.%s\n\n", CR_, CX_, lookback_days);
        }
        printf("    try: %s--window 1800%s   (locker ran long before touching files?)\n", CB_, CX_);
        printf("    or:  %s--key <locker-sample>%s   (campaign keys may have been rotated)\n", CB_, CX_);
        printf("    your originals are untouched. 24/7 assistance: %sinfo@ionsec.io%s\n", CB_, CX_);
        {
            time_t nowx = time(NULL);
            long drift = (long)nowx - (long)((wmin + wmax) / 2);
            if (!forced && drift > (long)window + 60)
                fprintf(stderr, "    hint: file mtimes are %ld s older than now - if the files were\n"
                                "    copied without preserving timestamps, re-run with\n"
                                "    --clock <detonation epoch> (or re-copy with rsync -a / tar).\n", drift);
            if (strstr(keymode, "embedded") && keyfile == NULL)
                fprintf(stderr, "    hint: if these files came from a different locker build, pass\n"
                                "    its ELF to --key (it may carry a rotated campaign key).\n");
        }
        return 1;
    }
clock_recovered:
    printf("\n%s[+] recovered stream%s — decrypting at clock %s%u%s\n\n",
           CG_, CX_, CB_, (unsigned)best_seed, CX_);

    /* decrypt pass (unchanged core) ----------------------------------- */
    for (int i = 0; i < nf; i++) ef[i].found = 0;
    sweep_seed(best_seed, PRNG_IDX, HASH_IDX, &pub, ef, nf, SEQMAX);
    mk1dir(outdir);
    int resolved = 0;
    for (int fi = 0; fi < nf; fi++) {
        if (!ef[fi].found) {
            printf("%s[!] not matched:%s %s\n", CY_, CX_, ef[fi].name);
            fflush(stdout);
            continue;
        }
        prng_state ps;
        build_stream(best_seed, PRNG_IDX, &ps);
        unsigned char key[32], iv[16];
        unsigned char blob[0x1000], blob2[0x1000];
        unsigned long bloblen = 0x800, blob2len = 0x800;
        for (int s = 0; s <= ef[fi].hit_seq; s++) {
            chacha20_prng_read(key, 32, &ps);
            chacha20_prng_read(iv, 16, &ps);
            if (s < ef[fi].hit_seq) {
                bloblen = 0x800; blob2len = 0x800;
                (void)rsa_encrypt_key_ex(key, 32, blob, &bloblen, (unsigned char *)"Rhysida-0.1", 0xb,
                                         &ps, PRNG_IDX, HASH_IDX, LTC_PKCS_1_OAEP, &pub);
                (void)rsa_encrypt_key_ex(iv, 16, blob2, &blob2len, (unsigned char *)"Rhysida-0.1", 0xb,
                                         &ps, PRNG_IDX, HASH_IDX, LTC_PKCS_1_OAEP, &pub);
            }
        }
        uint8_t *pt = (uint8_t *)malloc((size_t)ef[fi].plainlen);
        aes_ctr_dec(key, iv, ef[fi].data, (size_t)ef[fi].plainlen, pt);
        unsigned char dh[32]; unsigned long hl = 32;
        hash_memory(find_hash("sha256"), pt, (unsigned long)ef[fi].plainlen, dh, &hl);
        char dhhex[65]; for (int q = 0; q < 32; q++) sprintf(dhhex + q * 2, "%02x", dh[q]);
        char clean[MAXFNAME];
        snprintf(clean, MAXFNAME, "%s", ef[fi].name);
        char *sf = strstr(clean, ".rhysida");
        if (sf) *sf = 0;
        char outp[MAXFNAME + 512];
        snprintf(outp, sizeof outp, "%s/%s", outdir, clean);
        FILE *o = fopen(outp, "wb");
        int wok = 0;
        if (o) { wok = (fwrite(pt, 1, (size_t)ef[fi].plainlen, o) == (size_t)ef[fi].plainlen); fclose(o); }
        printf("%s[RESTORED]%s %s%s%s (seq %d, sha256 %s)\n",
               wok ? CG_ : CR_, CX_, CB_, outp, CX_, ef[fi].hit_seq, dhhex);
        fflush(stdout);
        if (keep_keys) {
            char kh2[65], ih2[33];
            for (int q = 0; q < 32; q++) sprintf(kh2 + q * 2, "%02x", key[q]);
            for (int q = 0; q < 16; q++) sprintf(ih2 + q * 2, "%02x", iv[q]);
            snprintf(outp, sizeof outp, "%s/key_report_%s.txt", outdir, clean);
            o = fopen(outp, "wb");
            if (o) { fprintf(o, "clock=%u seq=%d key=%s iv=%s\n", (unsigned)best_seed,
                             ef[fi].hit_seq, kh2, ih2); fclose(o); }
        }
        resolved++;
        free(pt);
    }

    printf("\n%s=== RESULT: %d/%d files restored (encryption clock %u) ===%s\n",
           CB_, resolved, nf, (unsigned)best_seed, CX_);
    printf("plaintext copies : %s\ninputs           : untouched\n\n", outdir);
    printf("%s%s%s\n", CD_, DISCLAIMER, CX_);
    printf(" 24/7 emergency response: %s%s/services/emergency-ir%s  |  %sinfo@ionsec.io%s\n\n",
           CC_, SITE_URL, CX_, CB_, CX_);
    char lstamp[160] = {0};
    char ts0[160] = {0};
    { char ttx[160] = {0}; stamp_valid(ttx, sizeof ttx); snprintf(lstamp, sizeof lstamp, "%s", accept_license ? "this run (--accept-license)" : (ttx[0] ? ttx : "this run (typed)")); }
    char eulav[16];
    snprintf(eulav, sizeof eulav, "%s", LICENSE_VERSION);
    write_report(outdir, target, outdir, ef, nf, resolved, lo, hi, best_seed, wall,
                 best_res == nf, keymode, lstamp, eulav);
    return 0;
}
/* tests/make_corpus.c — deterministic SYNTHETIC corpus generator for INSITO CI.
 *
 * TEST-ONLY. Rebuilds the Rhysida ESXi locker's encryption model in miniature,
 * exactly as insito.c replays it:
 *
 *   1) srand(seed) -> glibc rand() stream (insito carries its own glibc
 *      TYPE_3 rand() clone; the clone-vs-libc parity is asserted by recovery
 *      itself and by tests/insito_selftest.c when present),
 *   2) 40 entropy bytes  ent[i] = ((prng_idx + i + 1) * (rand() % 256)) % 256,
 *   3) one ChaCha20 PRNG: chacha20_prng_start/ready + add_entropy(ent,40),
 *      then one extra rand() draw (the locker's interleaved malloc draw) and
 *      one 8-byte self-test draw,
 *   4) per sequence: key[32] + iv[16] drawn sequentially, then
 *      RSA-4096-OAEP(label "Rhysida-0.1") wraps of the key and the IV — those
 *      wraps draw their OAEP randomness from the same live stream (that is
 *      what makes insito's trailer-matching oracle work),
 *   5) payload encrypted with AES-256-CTR (little-endian counter, block 0 = iv),
 *   6) file written as <name>.rhysida with the 0x40C-byte trailer
 *      [keyblob 512][len u32 LE = 512][ivblob 512][len u32 LE = 512][type u32 LE = 1],
 *   7) ciphertext mtime = CORPUS_SEED + MTIME_LAG + seq, so insito's default
 *      --window 600 sweep finds the true encryption clock as its first
 *      candidate (lo = wmin - window = CORPUS_SEED).
 *
 * The public key is the SAME pubkey_elf.h that insito is compiled against,
 * so the trailer wrappings are reproducible by insito's sweep oracle
 * byte-for-byte. The key embedded in pubkey_elf.h is a TEST-ONLY defensive
 * key; no live campaign material is used anywhere in this corpus.
 *
 * Decoy contents are deterministic ASCII decoys; two runs on the same seed
 * produce byte-identical corpora.
 *
 * Usage: make_corpus <expected_plaintext_dir> <datastore_dir> [n_files (1..64, default 12)]
 */

#include <tomcrypt.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <utime.h>

#include <pubkey_elf.h> /* shared TEST-ONLY embedded public key (see file header) */

extern const ltc_math_descriptor ltm_desc;

/* LTC's argchk is provided by the host program in this build (insito.c does
 * the same); the vendored archive does not export it. */
void crypt_argchk(const char *a, const char *b, int c) { (void)a; (void)b; (void)c; }

#define CORPUS_SEED 1719273600u /* locker start clock, fixed for reproducibility */
#define MTIME_LAG 600u /* ciphertext lag after seeding; keeps lo == CORPUS_SEED */
#define AES_KEY_LEN 32
#define AES_IV_LEN 16
#define RSA_BYTES 512             /* RSA-4096 wrapped output */
#define TRAILER_BYTES 1036        /* [keyblob512][len4][ivblob512][len4][type4] */
#define OAEP_LABEL "Rhysida-0.1"
#define OAEP_LABEL_LEN (sizeof(OAEP_LABEL) - 1)
#define DEFAULT_NFILES 12
#define MAX_NFILES 64

static void die(const char *msg, const char *arg)
{
    if (arg && *arg) {
        fprintf(stderr, "make_corpus: %s: %s\n", msg, arg);
    } else {
        fprintf(stderr, "make_corpus: %s\n", msg);
    }
    exit(1);
}

/* AES-256-CTR with a little-endian counter, byte-for-byte the same arithmetic
 * insito.c's aes_ctr_dec() reverses (same block construction, same ++-order). */
static void aes_ctr_xcrypt(const unsigned char key[AES_KEY_LEN],
                           const unsigned char iv16[AES_IV_LEN],
                           const unsigned char *in, size_t n, unsigned char *out)
{
    symmetric_key sk;
    if (aes_setup(key, AES_KEY_LEN, 0, &sk) != CRYPT_OK) {
        die("aes_setup failed", NULL);
    }
    unsigned char ctrb[16], ks[16];
    memcpy(ctrb, iv16, 16);
    for (size_t i = 0; i < n; i += 16) {
        aes_ecb_encrypt(ctrb, ks, &sk);
        for (int j = 0; j < 16; j++) { /* little-endian counter increment */
            ctrb[j] = (unsigned char)(ctrb[j] + 1);
            if (ctrb[j]) {
                break;
            }
        }
        size_t take = (n - i < 16) ? (n - i) : 16;
        for (size_t j = 0; j < take; j++) {
            out[i + j] = in[i + j] ^ ks[j];
        }
    }
    aes_done(&sk);
}

/* The locker's PRNG construction — verbatim mirror of insito.c's build_stream()
 * replay, with libc rand() standing in for the clone (parity is the point). */
static void build_stream(unsigned long seed, int prng_idx, prng_state *ps)
{
    srand((unsigned int)seed);
    unsigned char ent[40];
    for (int i = 0; i < 40; i++) {
        unsigned int rv = (unsigned int)rand() % 0x100u;
        ent[i] = (unsigned char)(((unsigned int)(prng_idx + i + 1) * rv) % 0x100u);
    }
    chacha20_prng_start(ps);
    chacha20_prng_ready(ps);
    chacha20_prng_add_entropy(ent, 0x28, ps);
    (void)rand(); /* the interleaved malloc-rand draw */
    unsigned char selftest[8];
    chacha20_prng_read(selftest, 8, ps); /* 8-byte self-test draw */
}

static void put_u32le(FILE *f, unsigned long v)
{
    fputc((int)(v & 0xFFul), f);
    fputc((int)((v >> 8) & 0xFFul), f);
    fputc((int)((v >> 16) & 0xFFul), f);
    fputc((int)((v >> 24) & 0xFFul), f);
}

static void check_w(FILE *f, const char *path)
{
    if (ferror(f) || fflush(f) != 0) {
        fclose(f);
        die("write failed", path);
    }
}

static size_t plain_size(unsigned seq)
{
    return 8192ul + ((unsigned long)seq * 3571ul) % 98304ul;
}

static void render_plaintext(unsigned seq, unsigned char *buf, size_t len)
{
    static const char ALPHA[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char head[96];
    int hl = snprintf(head, sizeof head,
                      "INSITO SYNTHETIC CORPUS decoy seq=%06u bytes=%zu\n", seq, len);
    if (hl <= 0 || (size_t)hl >= len) {
        die("render_plaintext: header does not fit", NULL);
    }
    memcpy(buf, head, (size_t)hl);
    for (size_t off = (size_t)hl; off < len; off++) {
        buf[off] = (unsigned char)ALPHA[(((unsigned long)seq * 7ul) + (off * 31ul)) % 62ul];
    }
}

static const char *DECOY_EXT[] = { "txt",  "vmdk", "log", "csv", "doc", "xls",
                                   "ppt",  "xml",  "conf", "bak", "sql", "eml" };

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4) {
        fprintf(stderr,
                "usage: make_corpus <expected_plaintext_dir> <datastore_dir> [n_files (1..%d, default %d)]\n",
                MAX_NFILES, DEFAULT_NFILES);
        return 2;
    }
    const char *pristine_dir = argv[1];
    const char *ds_dir = argv[2];
    int nfiles = (argc > 3) ? atoi(argv[3]) : DEFAULT_NFILES;
    if (nfiles < 1) {
        die("n_files must be >= 1", NULL);
    }
    if (nfiles > MAX_NFILES) {
        nfiles = MAX_NFILES;
    }

    /* LibTomCrypt wiring — mirrors insito.c main() exactly (stable indexes). */
    ltc_mp = ltm_desc;
    register_cipher(&aes_desc);
    register_hash(&chc_desc);
    register_hash(&sha256_desc);
    register_prng(&chacha20_prng_desc);
    int CIPHER = find_cipher("aes");
    chc_register(CIPHER);
    int HASH_IDX = find_hash("chc_hash");
    int PRNG_IDX = find_prng("chacha20");
    if (CIPHER < 0 || HASH_IDX < 0 || PRNG_IDX < 0) {
        die("libtomcrypt registration failed (aes/chc_hash/chacha20 missing)", NULL);
    }

    /* The embedded TEST-ONLY campaign public key, shared with insito via the
     * same pubkey_elf.h (identical rsa_set_key call as insito.c). */
    unsigned char E[3] = { 0x01, 0x00, 0x01 };
    rsa_key pub;
    if (rsa_set_key((unsigned char *)RHYSIDA_N, RHYSIDA_NLEN, E, 3, NULL, 0, &pub) != CRYPT_OK) {
        die("rsa_set_key failed (pubkey_elf.h / TEST-ONLY key)", NULL);
    }

    prng_state ps;
    build_stream(CORPUS_SEED, PRNG_IDX, &ps);

    unsigned char blob[RSA_BYTES + 16], blob2[RSA_BYTES + 16];

    for (unsigned seq = 0; seq < (unsigned)nfiles; seq++) {
        unsigned char key[32], iv[16];
        chacha20_prng_read(key, 32, &ps);
        chacha20_prng_read(iv, 16, &ps);

        size_t plen = plain_size(seq);
        unsigned char *pt = malloc(plen);
        unsigned char *ct = malloc(plen);
        unsigned char *chk = malloc(plen);
        if (!pt || !ct || !chk) {
            die("out of memory", NULL);
        }
        render_plaintext(seq, pt, plen);
        aes_ctr_xcrypt(key, iv, pt, plen, ct);   /* locker pass: plaintext -> ciphertext */
        aes_ctr_xcrypt(key, iv, ct, plen, chk);  /* self-check: decrypt must round-trip */
        if (memcmp(chk, pt, plen) != 0) {
            die("AES-256-CTR self-check failed (model mismatch)", NULL);
        }
        free(chk);

        /* OAEP wraps consume the same live stream (insito replays them for its
         * trailer-matching oracle). */
        unsigned long bloblen = sizeof blob, blob2len = sizeof blob2;
        if (rsa_encrypt_key_ex(key, 32, blob, &bloblen, (unsigned char *)OAEP_LABEL,
                               OAEP_LABEL_LEN, &ps, PRNG_IDX, HASH_IDX, LTC_PKCS_1_OAEP,
                               &pub) != CRYPT_OK || bloblen != RSA_BYTES) {
            die("RSA-4096-OAEP wrap of AES key failed", NULL);
        }
        if (rsa_encrypt_key_ex(iv, 16, blob2, &blob2len, (unsigned char *)OAEP_LABEL,
                               OAEP_LABEL_LEN, &ps, PRNG_IDX, HASH_IDX, LTC_PKCS_1_OAEP,
                               &pub) != CRYPT_OK || blob2len != RSA_BYTES) {
            die("RSA-4096-OAEP wrap of AES IV failed", NULL);
        }

        char name[64];
        snprintf(name, sizeof name, "decoy_%04u.%s", seq,
                 DECOY_EXT[seq % (sizeof(DECOY_EXT) / sizeof(DECOY_EXT[0]))]);
        char ppath[1024], dpath[1024], linebuf[128];
        snprintf(ppath, sizeof ppath, "%s/%s", pristine_dir, name);
        snprintf(dpath, sizeof dpath, "%s/%s.rhysida", ds_dir, name);

        FILE *fp = fopen(ppath, "wb");
        if (!fp || fwrite(pt, 1, plen, fp) != plen) {
            if (fp) {
                fclose(fp);
            }
            die("cannot write plaintext decoy", ppath);
        }
        check_w(fp, ppath);
        fclose(fp);
        free(pt);

        FILE *fd = fopen(dpath, "wb");
        if (!fd || fwrite(ct, 1, plen, fd) != plen) {
            if (fd) {
                fclose(fd);
            }
            die("cannot write encrypted decoy", dpath);
        }
        if (fwrite(blob, 1, RSA_BYTES, fd) != RSA_BYTES) {
            fclose(fd);
            die("cannot write key blob", dpath);
        }
        put_u32le(fd, RSA_BYTES);
        if (fwrite(blob2, 1, RSA_BYTES, fd) != RSA_BYTES) {
            fclose(fd);
            die("cannot write IV blob", dpath);
        }
        put_u32le(fd, RSA_BYTES);
        put_u32le(fd, 1); /* type = 1 */
        check_w(fd, dpath);
        fclose(fd);
        free(ct);

        unsigned long mt = (unsigned long)CORPUS_SEED + MTIME_LAG + seq;
        struct utimbuf tb;
        tb.actime = (time_t)mt;
        tb.modtime = (time_t)mt;
        if (utime(dpath, &tb) != 0) {
            die("utime failed", dpath);
        }

        snprintf(linebuf, sizeof linebuf, "[corpus] %s.rhysida seq=%u mtime=%lu bytes=%zu\n",
                 name, seq, mt, plen);
        fputs(linebuf, stdout);
    }

    rsa_free(&pub);
    printf("[corpus] done: %d deterministic synthetic decoys (seed=%lu, no live material)\n", nfiles,
           (unsigned long)CORPUS_SEED);
    return 0;
}

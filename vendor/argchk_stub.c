/* link stub: tests that define their own crypt_argchk (strong) win; the rest get a no-op */
__attribute__((weak)) void crypt_argchk(const char *v, const char *f, int l) { (void)v; (void)f; (void)l; }

/*
 * Tier 1 — Decrypt-into-externally-owned-pages (C / Linux kernel module).
 *
 * Synthesises the structural shape of CVE-2026-43284 (esp4/esp6) and
 * CVE-2026-43500 (rxrpc/rxkad). A receive-path function builds a
 * scatterlist directly over an SKB's pages and passes it to an AEAD
 * decrypt — without first ensuring the SKB's pages are kernel-owned.
 * When an attacker has spliced pipe pages into the SKB (via
 * splice/sendfile/MSG_SPLICE_PAGES + vmsplice page-cache aliasing),
 * the in-place decrypt corrupts attacker-readable backing memory.
 *
 * Argus emission target: `decrypt_into_external_pages_candidate`
 * (binary-scope, v1) and `decrypt_into_external_pages` (per-function,
 * v2 — pending).
 *
 * Build:
 *   This is a Linux kernel module fixture. Cross-compilation requires
 *   a kernel build environment (kernel headers, kbuild, etc.). On
 *   this host (Windows/MSVC) the fixture is provided as source for
 *   documentation; build_all.sh skips the .ko targets. To validate
 *   the detector against this fixture, build on a Linux host:
 *
 *     # On Linux with kernel-devel installed:
 *     make -C /lib/modules/$(uname -r)/build M=$(pwd)/source modules
 *
 *   Then point the runner at `source/vuln.ko`:
 *     python vulntest/runner.py --targets vulntest/tier1-single/\
 *       decrypt-external-pages/c/source/vuln.ko
 *
 * Knowledge: [[Memory/Knowledge/dirty_frag_decrypt_into_external_pages]]
 * CWE: 119, 787, 345.
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>

/* Receive-path entry. Caller hands in a (potentially attacker-
   influenced) SKB whose paged fragments may be pipe-backed. The
   bug: we build a scatterlist directly over those pages and pass
   it to crypto_aead_decrypt without privately-own gating. */
int dirty_frag_recv(struct sk_buff *skb, struct aead_request *req)
{
    struct scatterlist sg[8];
    int ret;

    /* sink #1: build sg from SKB pages — no skb_cow_data call. */
    sg_init_table(sg, 8);
    ret = skb_to_sgvec(skb, sg, 0, skb->len);
    if (ret < 0)
        return ret;

    /* sink #2: in-place decrypt over those pages. If skb's pages
       are externally-owned (pipe pages from splice/vmsplice), the
       plaintext lands in attacker-influenced memory. */
    aead_request_set_crypt(req, sg, sg, skb->len, NULL);
    return crypto_aead_decrypt(req);
}

static int __init vuln_init(void) { return 0; }
static void __exit vuln_exit(void) { }

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Argus VulnTest: decrypt-into-externally-owned-pages");

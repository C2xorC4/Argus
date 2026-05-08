/*
 * Tier 1 — Decrypt-into-externally-owned-pages — remediation.
 *
 * Calls skb_cow_data() before building the scatterlist + decrypting.
 * skb_cow_data ensures the SKB's pages are privately owned by the
 * kernel — copying out of any external/shared/pipe pages first.
 * The subsequent in-place decrypt now writes only to kernel-owned
 * memory; attacker-readable backing pages are no longer reachable.
 *
 * v1 detector behaviour: still emits the
 * `decrypt_into_external_pages_candidate` if it doesn't see
 * `skb_cow_data` in the import set. With the fix, skb_cow_data IS
 * imported — v1 suppresses (privately-own gate present).
 *
 * v2 detector (pending): per-function CFG check confirms
 * skb_cow_data dominates the decrypt call site.
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>

int dirty_frag_recv(struct sk_buff *skb, struct aead_request *req)
{
    struct scatterlist sg[8];
    int ret;
    int trailer_pos = 0;

    /* fix: privately-own gate. After this call, all SKB pages are
       owned by the kernel (or the call returned an error). */
    ret = skb_cow_data(skb, 0, NULL);
    if (ret < 0)
        return ret;

    sg_init_table(sg, 8);
    ret = skb_to_sgvec(skb, sg, 0, skb->len);
    if (ret < 0)
        return ret;

    aead_request_set_crypt(req, sg, sg, skb->len, NULL);
    return crypto_aead_decrypt(req);
}

static int __init vuln_init(void) { return 0; }
static void __exit vuln_exit(void) { }

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Argus VulnTest: decrypt-external-pages remediation");

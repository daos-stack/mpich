/*
 * Copyright (C) by Argonne National Laboratory
 *     See COPYRIGHT in top-level directory
 */

#include "ad_daos.h"
#include "gurt/hash.h"
#include <gurt/common.h>

static struct d_hash_table *coh_hash;
static struct d_hash_table *poh_hash;

enum {
    DAOS_POOL,
    DAOS_CONT,
};

static inline struct adio_daos_hdl *hdl_obj(d_list_t * rlink)
{
    return container_of(rlink, struct adio_daos_hdl, entry);
}

static bool
key_cmp(struct d_hash_table *htable, d_list_t * rlink, const void *key, unsigned int ksize)
{
    struct adio_daos_hdl *hdl = hdl_obj(rlink);

    if (hdl->label)
        return (strcmp(hdl->label, key) == 0);
    else
        return (uuid_compare(hdl->uuid, key) == 0);
}

static void rec_addref(struct d_hash_table *htable, d_list_t * rlink)
{
    hdl_obj(rlink)->ref++;
}

static bool rec_decref(struct d_hash_table *htable, d_list_t * rlink)
{
    struct adio_daos_hdl *hdl = hdl_obj(rlink);

    assert(hdl->ref > 0);
    hdl->ref--;
    return (hdl->ref == 0);
}

static void rec_free(struct d_hash_table *htable, d_list_t * rlink)
{
    struct adio_daos_hdl *hdl = hdl_obj(rlink);

    assert(d_hash_rec_unlinked(&hdl->entry));
    assert(hdl->ref == 0);

    if (hdl->type == DAOS_POOL)
        daos_pool_disconnect(hdl->open_hdl, NULL);
    else if (hdl->type == DAOS_CONT) {
        dfs_umount(hdl->dfs);
        daos_cont_close(hdl->open_hdl, NULL);
    } else
        assert(0);
    if (hdl->label)
        ADIOI_Free(hdl->label);
    ADIOI_Free(hdl);
}

static uint32_t rec_hash(struct d_hash_table *htable, d_list_t * rlink)
{
    struct adio_daos_hdl *hdl = hdl_obj(rlink);

    if (hdl->label) {
        return d_hash_string_u32(hdl->label, strlen(hdl->label));
    } else {
        uint32_t *retp = (uint32_t *) hdl->uuid;
        return *retp;
    }
}

static d_hash_table_ops_t hdl_hash_ops = {
    .hop_key_cmp = key_cmp,
    .hop_rec_addref = rec_addref,
    .hop_rec_decref = rec_decref,
    .hop_rec_free = rec_free,
    .hop_rec_hash = rec_hash
};

int adio_daos_hash_init(void)
{
    int rc;

    rc = d_hash_table_create(D_HASH_FT_EPHEMERAL | D_HASH_FT_LRU,
                             4, NULL, &hdl_hash_ops, &poh_hash);
    if (rc)
        return rc;

    return d_hash_table_create(D_HASH_FT_EPHEMERAL | D_HASH_FT_LRU,
                               4, NULL, &hdl_hash_ops, &coh_hash);
}

void adio_daos_hash_finalize(void)
{
    d_list_t *rlink;

    while (1) {
        rlink = d_hash_rec_first(coh_hash);
        if (rlink == NULL)
            break;

        d_hash_rec_decref(coh_hash, rlink);
    }
    d_hash_table_destroy(coh_hash, false);

    while (1) {
        rlink = d_hash_rec_first(poh_hash);
        if (rlink == NULL)
            break;

        d_hash_rec_decref(poh_hash, rlink);
    }
    d_hash_table_destroy(poh_hash, false);
}

struct adio_daos_hdl *adio_daos_poh_lookup(struct duns_attr_t *attr)
{
    d_list_t *rlink;

#if DAOS_API_VERSION_MAJOR > 1 || DAOS_API_VERSION_MINOR > 2
    if (attr->da_pool_label)
        rlink = d_hash_rec_find(poh_hash, attr->da_pool_label, strlen(attr->da_pool_label));
    else
#endif
        rlink = d_hash_rec_find(poh_hash, attr->da_puuid, sizeof(attr->da_puuid));
    if (rlink == NULL)
        return NULL;

    return hdl_obj(rlink);
}

void adio_daos_poh_release(struct adio_daos_hdl *hdl)
{
    d_hash_rec_decref(poh_hash, &hdl->entry);
}

int adio_daos_poh_insert(struct duns_attr_t *attr, daos_handle_t poh, struct adio_daos_hdl **hdl)
{
    struct adio_daos_hdl *phdl;
    int rc;

    phdl = (struct adio_daos_hdl *) ADIOI_Calloc(1, sizeof(struct adio_daos_hdl));
    if (phdl == NULL)
        return -1;

    phdl->type = DAOS_POOL;
    phdl->open_hdl.cookie = poh.cookie;
    phdl->ref = 2;
#if DAOS_API_VERSION_MAJOR > 1 || DAOS_API_VERSION_MINOR > 2
    if (attr->da_pool_label) {
        phdl->label = ADIOI_Strdup(attr->da_pool_label);
        rc = d_hash_rec_insert(poh_hash, phdl->label, strlen(phdl->label) + 1, &phdl->entry, true);
    } else {
#endif
        uuid_copy(phdl->uuid, attr->da_puuid);
        rc = d_hash_rec_insert(poh_hash, phdl->uuid, sizeof(phdl->uuid), &phdl->entry, true);
#if DAOS_API_VERSION_MAJOR > 1 || DAOS_API_VERSION_MINOR > 2
    }
#endif
    if (rc) {
        PRINT_MSG(stderr, "Failed to add phdl to hashtable (%d)\n", rc);
        goto free_hdl;
    }

    *hdl = phdl;

    return 0;

  free_hdl:
    ADIOI_Free(phdl);
    return rc;
}

int adio_daos_poh_lookup_connect(struct duns_attr_t *attr, struct adio_daos_hdl **hdl)
{
    struct adio_daos_hdl *phdl;
    char *group = NULL;
    daos_pool_info_t pool_info;
    daos_handle_t poh;
    int rc;

    phdl = adio_daos_poh_lookup(attr);
    if (phdl != NULL) {
        *hdl = phdl;
        return 0;
    }

    /** Get the DAOS system name group from env variable */
    group = getenv("DAOS_GROUP");

#if !defined(DAOS_API_VERSION_MAJOR) || DAOS_API_VERSION_MAJOR < 1
    /** Get the SVCL from env variable */
    char *svcl_str = NULL;
    d_rank_list_t *svcl = NULL;

    svcl_str = getenv("DAOS_SVCL");
    if (svcl_str != NULL) {
        svcl = daos_rank_list_parse(svcl_str, ":");
        if (svcl == NULL) {
            PRINT_MSG(stderr, "Failed to parse SVC list env\n");
            rc = -1;
            goto free_hdl;
        }
    }

    rc = daos_pool_connect(attr->da_puuid, group, svcl, DAOS_PC_RW, &poh, &pool_info, NULL);
    d_rank_list_free(svcl);
#else
#if DAOS_API_VERSION_MAJOR > 1 || DAOS_API_VERSION_MINOR > 2
    if (attr->da_pool_label)
        rc = daos_pool_connect_by_label(attr->da_pool_label, group, DAOS_PC_RW, &poh,
                                        &pool_info, NULL);
    else
#endif
        rc = daos_pool_connect(attr->da_puuid, group, DAOS_PC_RW, &poh, &pool_info, NULL);
#endif
    if (rc < 0) {
        PRINT_MSG(stderr, "Failed to connect to pool (%d)\n", rc);
        goto free_hdl;
    }

    rc = adio_daos_poh_insert(attr, poh, &phdl);
    if (rc) {
        PRINT_MSG(stderr, "Failed to add phdl to hashtable (%d)\n", rc);
        goto err_pool;
    }

    *hdl = phdl;

    return 0;

  err_pool:
    daos_pool_disconnect(phdl->open_hdl, NULL);
  free_hdl:
    ADIOI_Free(phdl);
    return rc;
}

struct adio_daos_hdl *adio_daos_coh_lookup(struct duns_attr_t *attr)
{
    d_list_t *rlink;

#if DAOS_API_VERSION_MAJOR > 1 || DAOS_API_VERSION_MINOR > 2
    if (attr->da_cont_label)
        rlink = d_hash_rec_find(coh_hash, attr->da_cont_label, strlen(attr->da_cont_label));
    else
#endif
        rlink = d_hash_rec_find(coh_hash, attr->da_cuuid, sizeof(attr->da_cuuid));
    if (rlink == NULL)
        return NULL;

    return hdl_obj(rlink);
}

void adio_daos_coh_release(struct adio_daos_hdl *hdl)
{
    d_hash_rec_decref(coh_hash, &hdl->entry);
}

int adio_daos_coh_insert(struct duns_attr_t *attr, daos_handle_t coh, dfs_t * dfs,
                         struct adio_daos_hdl **hdl)
{
    struct adio_daos_hdl *co_hdl;
    int rc;

    co_hdl = (struct adio_daos_hdl *) ADIOI_Calloc(1, sizeof(struct adio_daos_hdl));
    if (co_hdl == NULL)
        return -1;

    co_hdl->type = DAOS_CONT;
    co_hdl->dfs = dfs;
    co_hdl->open_hdl.cookie = coh.cookie;
    co_hdl->ref = 2;
#if DAOS_API_VERSION_MAJOR > 1 || DAOS_API_VERSION_MINOR > 2
    if (attr->da_cont_label) {
        co_hdl->label = ADIOI_Strdup(attr->da_cont_label);
        rc = d_hash_rec_insert(coh_hash, co_hdl->label, strlen(co_hdl->label) + 1,
                               &co_hdl->entry, true);
    } else {
#endif
        uuid_copy(co_hdl->uuid, attr->da_cuuid);
        rc = d_hash_rec_insert(coh_hash, co_hdl->uuid, sizeof(co_hdl->uuid), &co_hdl->entry, true);
#if DAOS_API_VERSION_MAJOR > 1 || DAOS_API_VERSION_MINOR > 2
    }
#endif
    if (rc) {
        PRINT_MSG(stderr, "Failed to add co_hdl to hashtable (%d)\n", rc);
        goto err_coh;
    }

    *hdl = co_hdl;

    return 0;

  err_coh:
    ADIOI_Free(co_hdl);
    return rc;
}

int
adio_daos_coh_lookup_create(daos_handle_t poh, struct duns_attr_t *attr, int amode,
                            bool create, struct adio_daos_hdl **hdl)
{
    struct adio_daos_hdl *co_hdl;
    daos_handle_t coh;
    dfs_t *dfs;
    int rc;

    co_hdl = adio_daos_coh_lookup(attr);
    if (co_hdl != NULL) {
        *hdl = co_hdl;
        return 0;
    }

    /* Try to open the DAOS container first */
#if DAOS_API_VERSION_MAJOR > 1 || DAOS_API_VERSION_MINOR > 2
    if (attr->da_cont_label)
        rc = daos_cont_open_by_label(poh, attr->da_cont_label, DAOS_COO_RW, &coh, NULL, NULL);
    else
#endif
        rc = daos_cont_open(poh, attr->da_cuuid, DAOS_COO_RW, &coh, NULL, NULL);
    /* If fails with NOEXIST we can create it then reopen if create mode */
    if (rc == -DER_NONEXIST && create) {
#if DAOS_API_VERSION_MAJOR > 1 || DAOS_API_VERSION_MINOR > 2
        if (attr->da_cont_label) {
            PRINT_MSG(stderr, "Container access with label requires container to be created.\n");
            goto free_coh;
        }
#endif
        rc = dfs_cont_create(poh, attr->da_cuuid, NULL, &coh, &dfs);
        /** if someone got there first, re-open*/
        if (rc == EEXIST) {
            rc = daos_cont_open(poh, attr->da_cuuid, DAOS_COO_RW, &coh, NULL, NULL);
            if (rc) {
                PRINT_MSG(stderr, "Failed to create DFS container (%d)\n", rc);
                goto free_coh;
            }
            rc = dfs_mount(poh, coh, amode, &dfs);
            if (rc) {
                PRINT_MSG(stderr, "Failed to mount DFS namesapce (%d)\n", rc);
                goto err_cont;
            }
        } else if (rc) {
            PRINT_MSG(stderr, "Failed to create DFS container (%d)\n", rc);
            goto free_coh;
        }
    } else if (rc == 0) {
        /* Mount a DFS namespace on the container */
        rc = dfs_mount(poh, coh, amode, &dfs);
        if (rc) {
            PRINT_MSG(stderr, "Failed to mount DFS namespace (%d)\n", rc);
            goto err_cont;
        }
    } else {
        goto free_coh;
    }

    rc = adio_daos_coh_insert(attr, coh, dfs, &co_hdl);
    if (rc) {
        PRINT_MSG(stderr, "Failed to add container hdl to hashtable (%d)\n", rc);
        goto err_dfs;
    }

    *hdl = co_hdl;
    return 0;

  err_dfs:
    dfs_umount(dfs);
  err_cont:
    daos_cont_close(coh, NULL);
  free_coh:
    ADIOI_Free(co_hdl);
    return rc;
}

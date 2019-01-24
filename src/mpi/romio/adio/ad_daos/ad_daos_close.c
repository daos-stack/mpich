/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil ; -*- */
/*
 *
 * Copyright (C) 1997 University of Chicago.
 * See COPYRIGHT notice in top-level directory.
 *
 * Copyright (C) 2018 Intel Corporation
 *
 * GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
 * The Government's rights to use, modify, reproduce, release, perform, display,
 * or disclose this software are subject to the terms of the Apache License as
 * provided in Contract No. 8F-30005.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */

#include "ad_daos.h"

void ADIOI_DAOS_Close(ADIO_File fd, int *error_code)
{
    int rank;
    struct ADIO_DAOS_cont *cont = (struct ADIO_DAOS_cont *)fd->fs_ptr;
    static char myname[] = "ADIOI_DAOS_CLOSE";
    int rc;

    if (cont->amode == DAOS_COO_RW)
        adio_daos_sync_ranks(fd->comm);
    else
        MPI_Barrier(fd->comm);

    MPI_Comm_rank(fd->comm, &rank);

    if (rank == 0) {
        /* release the dfs object handle for the file. */
        rc = dfs_release(cont->obj);
        if (rc) {
            PRINT_MSG(stderr, "dfs_release() failed (%d)\n", rc);
            goto bcast_rc;
        }

        rc = dfs_umount(cont->dfs);
        if (rc) {
            PRINT_MSG(stderr, "dfs_umount() failed (%d)\n", rc);
            goto bcast_rc;
        }
    }

bcast_rc:
    /* bcast the return code to the other ranks */
    MPI_Bcast(&rc, 1, MPI_INT, 0, fd->comm);
    if (rc != 0) {
        *error_code = MPIO_Err_create_code(MPI_SUCCESS,
                                           MPIR_ERR_RECOVERABLE,
                                           myname, __LINE__,
                                           ADIOI_DAOS_error_convert(rc),
                                           "Failed DFS umount", 0);
        return;
    }

    /* array is closed on rank 0 in dfs_release(), close it on the other ranks */
    if (rank != 0) {
        rc = daos_array_close(cont->oh, NULL);
        if (rc != 0) {
            PRINT_MSG(stderr, "daos_array_close() failed (%d)\n", rc);
            *error_code = MPIO_Err_create_code(MPI_SUCCESS,
                                               MPIR_ERR_RECOVERABLE,
                                               myname, __LINE__,
                                               ADIOI_DAOS_error_convert(rc),
                                               "Array Close failed", 0);
            return;
        }
    }

    /* close the container handle if it's created with l2g,g2l, 
       otherwise just decrement ref count on the container info in the hashtable. */
    if (cont->c) {
        adio_daos_cont_release(cont->c);
        cont->c = NULL;
    } else {
        rc = daos_cont_close(cont->coh, NULL);
        if (rc != 0) {
            PRINT_MSG(stderr, "daos_cont_close() failed (%d)\n", rc);
            *error_code = MPIO_Err_create_code(MPI_SUCCESS,
                                               MPIR_ERR_RECOVERABLE,
                                               myname, __LINE__,
                                               ADIOI_DAOS_error_convert(rc),
                                               "Container Close failed", 0);
            return;
        }
    }

    if (cont->p) {
        adio_daos_poh_release(cont->p);
        cont->p = NULL;
    } else {
        rc = daos_pool_disconnect(cont->poh, NULL);
        if (rc != 0) {
            PRINT_MSG(stderr, "daos_pool_disconnect() failed (%d)\n", rc);
            *error_code = MPIO_Err_create_code(MPI_SUCCESS,
                                               MPIR_ERR_RECOVERABLE,
                                               myname, __LINE__,
                                               ADIOI_DAOS_error_convert(rc),
                                               "Pool Disconnect failed", 0);
            return;
        }
    }

    free(cont->obj_name);
    free(cont->cont_name);
    ADIOI_Free(fd->fs_ptr);
    fd->fs_ptr = NULL;

    *error_code = MPI_SUCCESS;
}
/*
 * vim: ts=8 sts=4 sw=4 noexpandtab
 */

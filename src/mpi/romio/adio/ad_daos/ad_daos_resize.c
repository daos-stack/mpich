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

void ADIOI_DAOS_Resize(ADIO_File fd, ADIO_Offset size, int *error_code)
{
    int ret, rank;
    struct ADIO_DAOS_cont *cont = fd->fs_ptr;
    static char myname[] = "ADIOI_DAOS_RESIZE";

    *error_code = MPI_SUCCESS;

    MPI_Comm_rank(fd->comm, &rank);
    adio_daos_sync_ranks(fd->comm);
    if (rank == fd->hints->ranklist[0]) {
	ret = daos_array_set_size(cont->oh, DAOS_TX_NONE, size, NULL);
	MPI_Bcast(&ret, 1, MPI_INT, fd->hints->ranklist[0], fd->comm);
    } else  {
	MPI_Bcast(&ret, 1, MPI_INT, fd->hints->ranklist[0], fd->comm);
    }
    adio_daos_sync_ranks(fd->comm);

    /* --BEGIN ERROR HANDLING-- */
    if (ret != 0) {
	*error_code = MPIO_Err_create_code(MPI_SUCCESS,
					   MPIR_ERR_RECOVERABLE,
					   myname, __LINE__,
					   ADIOI_DAOS_error_convert(ret),
					   "Error in daos_array_set_size", 0);
	return;
    }
    /* --END ERROR HANDLING-- */
}

/*
 * Copyright (C) by Argonne National Laboratory
 *     See COPYRIGHT in top-level directory
 */

#ifndef CH4R_PROBE_H_INCLUDED
#define CH4R_PROBE_H_INCLUDED

#include "ch4_impl.h"

MPL_STATIC_INLINE_PREFIX int MPIDIG_mpi_iprobe(int source, int tag, MPIR_Comm * comm,
                                               int context_offset, int *flag, MPI_Status * status)
{
    int mpi_errno = MPI_SUCCESS;
    MPIR_Request *unexp_req;
    MPIR_FUNC_VERBOSE_STATE_DECL(MPID_STATE_MPIDIG_MPI_IPROBE);
    MPIR_FUNC_VERBOSE_ENTER(MPID_STATE_MPIDIG_MPI_IPROBE);
    MPID_THREAD_CS_ENTER(VCI, MPIDI_VCI(0).lock);

    MPIR_Context_id_t context_id = comm->recvcontext_id + context_offset;

    /* MPIDI_CS_ENTER(); */
    unexp_req =
        MPIDIG_rreq_find(source, tag, context_id, &MPIDI_global.unexp_list, MPIDIG_PT2PT_UNEXP);

    if (unexp_req) {
        *flag = 1;
        unexp_req->status.MPI_ERROR = MPI_SUCCESS;
        unexp_req->status.MPI_SOURCE = MPIDIG_REQUEST(unexp_req, rank);
        unexp_req->status.MPI_TAG = MPIDIG_REQUEST(unexp_req, tag);
        MPIR_STATUS_SET_COUNT(unexp_req->status, MPIDIG_REQUEST(unexp_req, count));

        MPIR_Request_extract_status(unexp_req, status);
    } else {
        *flag = 0;
    }
    /* MPIDI_CS_EXIT(); */

    MPID_THREAD_CS_EXIT(VCI, MPIDI_VCI(0).lock);
    MPIR_FUNC_VERBOSE_EXIT(MPID_STATE_MPIDIG_MPI_IPROBE);
    return mpi_errno;
}

MPL_STATIC_INLINE_PREFIX int MPIDIG_mpi_improbe(int source, int tag, MPIR_Comm * comm,
                                                int context_offset, int *flag,
                                                MPIR_Request ** message, MPI_Status * status)
{
    int mpi_errno = MPI_SUCCESS;
    MPIR_Request *unexp_req;

    MPIR_FUNC_VERBOSE_STATE_DECL(MPID_STATE_MPIDIG_MPI_IMPROBE);
    MPIR_FUNC_VERBOSE_ENTER(MPID_STATE_MPIDIG_MPI_IMPROBE);
    MPID_THREAD_CS_ENTER(VCI, MPIDI_VCI(0).lock);

    MPIR_Context_id_t context_id = comm->recvcontext_id + context_offset;

    /* MPIDI_CS_ENTER(); */
    unexp_req =
        MPIDIG_rreq_dequeue(source, tag, context_id, &MPIDI_global.unexp_list, MPIDIG_PT2PT_UNEXP);

    if (unexp_req) {
        *flag = 1;
        *message = unexp_req;

        (*message)->kind = MPIR_REQUEST_KIND__MPROBE;
        (*message)->comm = comm;
        MPIR_Comm_add_ref(comm);

        unexp_req->status.MPI_ERROR = MPI_SUCCESS;
        unexp_req->status.MPI_SOURCE = MPIDIG_REQUEST(unexp_req, rank);
        unexp_req->status.MPI_TAG = MPIDIG_REQUEST(unexp_req, tag);
        MPIR_STATUS_SET_COUNT(unexp_req->status, MPIDIG_REQUEST(unexp_req, count));
        MPIDIG_REQUEST(unexp_req, req->status) |= MPIDIG_REQ_UNEXP_DQUED;

        MPIR_Request_extract_status(unexp_req, status);
    } else {
        *flag = 0;
    }
    /* MPIDI_CS_EXIT(); */

    MPID_THREAD_CS_EXIT(VCI, MPIDI_VCI(0).lock);
    MPIR_FUNC_VERBOSE_EXIT(MPID_STATE_MPIDIG_MPI_IMPROBE);
    return mpi_errno;
}

#endif /* CH4R_PROBE_H_INCLUDED */

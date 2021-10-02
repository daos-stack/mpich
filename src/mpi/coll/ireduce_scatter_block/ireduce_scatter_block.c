/*
 * Copyright (C) by Argonne National Laboratory
 *     See COPYRIGHT in top-level directory
 */

#include "mpiimpl.h"
/* for MPIR_TSP_sched_t */
#include "tsp_gentran.h"
#include "gentran_utils.h"
#include "../ireduce_scatter_block/ireduce_scatter_block_tsp_recexch_algos_prototypes.h"

/*
=== BEGIN_MPI_T_CVAR_INFO_BLOCK ===

cvars:
    - name        : MPIR_CVAR_IREDUCE_SCATTER_BLOCK_RECEXCH_KVAL
      category    : COLLECTIVE
      type        : int
      default     : 2
      class       : none
      verbosity   : MPI_T_VERBOSITY_USER_BASIC
      scope       : MPI_T_SCOPE_ALL_EQ
      description : >-
        k value for recursive exchange based ireduce_scatter_block

    - name        : MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTRA_ALGORITHM
      category    : COLLECTIVE
      type        : enum
      default     : auto
      class       : none
      verbosity   : MPI_T_VERBOSITY_USER_BASIC
      scope       : MPI_T_SCOPE_ALL_EQ
      description : |-
        Variable to select ireduce_scatter_block algorithm
        auto - Internal algorithm selection (can be overridden with MPIR_CVAR_COLL_SELECTION_TUNING_JSON_FILE)
        sched_auto - Internal algorithm selection for sched-based algorithms
        sched_noncommutative     - Force noncommutative algorithm
        sched_recursive_doubling - Force recursive doubling algorithm
        sched_pairwise           - Force pairwise algorithm
        sched_recursive_halving  - Force recursive halving algorithm
        gentran_recexch          - Force generic transport recursive exchange algorithm

    - name        : MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTER_ALGORITHM
      category    : COLLECTIVE
      type        : enum
      default     : auto
      class       : none
      verbosity   : MPI_T_VERBOSITY_USER_BASIC
      scope       : MPI_T_SCOPE_ALL_EQ
      description : |-
        Variable to select ireduce_scatter_block algorithm
        auto - Internal algorithm selection (can be overridden with MPIR_CVAR_COLL_SELECTION_TUNING_JSON_FILE)
        sched_auto - Internal algorithm selection for sched-based algorithms
        sched_remote_reduce_local_scatterv - Force remote-reduce-local-scatterv algorithm

    - name        : MPIR_CVAR_IREDUCE_SCATTER_BLOCK_DEVICE_COLLECTIVE
      category    : COLLECTIVE
      type        : boolean
      default     : true
      class       : none
      verbosity   : MPI_T_VERBOSITY_USER_BASIC
      scope       : MPI_T_SCOPE_ALL_EQ
      description : >-
        This CVAR is only used when MPIR_CVAR_DEVICE_COLLECTIVES
        is set to "percoll".  If set to true, MPI_Ireduce_scatter_block will
        allow the device to override the MPIR-level collective
        algorithms.  The device might still call the MPIR-level
        algorithms manually.  If set to false, the device-override
        will be disabled.

=== END_MPI_T_CVAR_INFO_BLOCK ===
*/

int MPIR_Ireduce_scatter_block_allcomm_sched_auto(const void *sendbuf, void *recvbuf,
                                                  MPI_Aint recvcount, MPI_Datatype datatype,
                                                  MPI_Op op, MPIR_Comm * comm_ptr,
                                                  bool is_persistent, void **sched_p,
                                                  enum MPIR_sched_type *sched_type_p)
{
    int mpi_errno = MPI_SUCCESS;

    MPIR_Csel_coll_sig_s coll_sig = {
        .coll_type = MPIR_CSEL_COLL_TYPE__IREDUCE_SCATTER_BLOCK,
        .comm_ptr = comm_ptr,

        .u.ireduce_scatter_block.sendbuf = sendbuf,
        .u.ireduce_scatter_block.recvbuf = recvbuf,
        .u.ireduce_scatter_block.recvcount = recvcount,
        .u.ireduce_scatter_block.datatype = datatype,
        .u.ireduce_scatter_block.op = op,
    };

    MPII_Csel_container_s *cnt = MPIR_Csel_search(comm_ptr->csel_comm, coll_sig);
    MPIR_Assert(cnt);

    switch (cnt->id) {
        /* *INDENT-OFF* */
        case MPII_CSEL_CONTAINER_TYPE__ALGORITHM__MPIR_Ireduce_scatter_block_intra_gentran_recexch:
            MPII_GENTRAN_CREATE_SCHED_P();
            mpi_errno =
                MPIR_TSP_Ireduce_scatter_block_sched_intra_recexch(sendbuf, recvbuf, recvcount,
                                                                   datatype, op, comm_ptr,
                                                                   cnt->u.ireduce_scatter_block.
                                                                   intra_gentran_recexch.k,
                                                                   *sched_p);
            break;

        case MPII_CSEL_CONTAINER_TYPE__ALGORITHM__MPIR_Ireduce_scatter_block_intra_sched_auto:
            MPII_SCHED_CREATE_SCHED_P();
            mpi_errno = MPIR_Ireduce_scatter_block_intra_sched_auto(sendbuf, recvbuf, recvcount,
                                                                    datatype, op, comm_ptr,
                                                                    *sched_p);
            break;

        case MPII_CSEL_CONTAINER_TYPE__ALGORITHM__MPIR_Ireduce_scatter_block_intra_sched_noncommutative:
            MPII_SCHED_CREATE_SCHED_P();
            mpi_errno =
                MPIR_Ireduce_scatter_block_intra_sched_noncommutative(sendbuf, recvbuf, recvcount,
                                                                      datatype, op, comm_ptr,
                                                                      *sched_p);
            break;

        case MPII_CSEL_CONTAINER_TYPE__ALGORITHM__MPIR_Ireduce_scatter_block_intra_sched_pairwise:
            MPII_SCHED_CREATE_SCHED_P();
            mpi_errno = MPIR_Ireduce_scatter_block_intra_sched_pairwise(sendbuf, recvbuf, recvcount,
                                                                        datatype, op, comm_ptr,
                                                                        *sched_p);
            break;

        case MPII_CSEL_CONTAINER_TYPE__ALGORITHM__MPIR_Ireduce_scatter_block_intra_sched_recursive_doubling:
            MPII_SCHED_CREATE_SCHED_P();
            mpi_errno =
                MPIR_Ireduce_scatter_block_intra_sched_recursive_doubling(sendbuf, recvbuf,
                                                                          recvcount, datatype, op,
                                                                          comm_ptr, *sched_p);
            break;

        case MPII_CSEL_CONTAINER_TYPE__ALGORITHM__MPIR_Ireduce_scatter_block_intra_sched_recursive_halving:
            MPII_SCHED_CREATE_SCHED_P();
            mpi_errno =
                MPIR_Ireduce_scatter_block_intra_sched_recursive_halving(sendbuf, recvbuf,
                                                                         recvcount, datatype, op,
                                                                         comm_ptr, *sched_p);
            break;

        case MPII_CSEL_CONTAINER_TYPE__ALGORITHM__MPIR_Ireduce_scatter_block_inter_sched_auto:
            MPII_SCHED_CREATE_SCHED_P();
            mpi_errno = MPIR_Ireduce_scatter_block_inter_sched_auto(sendbuf, recvbuf, recvcount,
                                                                    datatype, op, comm_ptr,
                                                                    *sched_p);
            break;

        case MPII_CSEL_CONTAINER_TYPE__ALGORITHM__MPIR_Ireduce_scatter_block_inter_sched_remote_reduce_local_scatterv:
            MPII_SCHED_CREATE_SCHED_P();
            mpi_errno =
                MPIR_Ireduce_scatter_block_inter_sched_remote_reduce_local_scatterv(sendbuf,
                                                                                    recvbuf,
                                                                                    recvcount,
                                                                                    datatype, op,
                                                                                    comm_ptr,
                                                                                    *sched_p);
            break;

        default:
            MPIR_Assert(0);
        /* *INDENT-ON* */
    }

  fn_exit:
    return mpi_errno;
  fn_fail:
    goto fn_exit;
}

int MPIR_Ireduce_scatter_block_intra_sched_auto(const void *sendbuf, void *recvbuf,
                                                MPI_Aint recvcount, MPI_Datatype datatype,
                                                MPI_Op op, MPIR_Comm * comm_ptr, MPIR_Sched_t s)
{
    int mpi_errno = MPI_SUCCESS;
    int is_commutative;
    int total_count, type_size, nbytes;
    int comm_size;

    is_commutative = MPIR_Op_is_commutative(op);

    comm_size = comm_ptr->local_size;
    total_count = recvcount * comm_size;
    if (total_count == 0) {
        goto fn_exit;
    }
    MPIR_Datatype_get_size_macro(datatype, type_size);
    nbytes = total_count * type_size;

    /* select an appropriate algorithm based on commutivity and message size */
    if (is_commutative && (nbytes < MPIR_CVAR_REDUCE_SCATTER_COMMUTATIVE_LONG_MSG_SIZE)) {
        mpi_errno =
            MPIR_Ireduce_scatter_block_intra_sched_recursive_halving(sendbuf, recvbuf, recvcount,
                                                                     datatype, op, comm_ptr, s);
        MPIR_ERR_CHECK(mpi_errno);
    } else if (is_commutative && (nbytes >= MPIR_CVAR_REDUCE_SCATTER_COMMUTATIVE_LONG_MSG_SIZE)) {
        mpi_errno =
            MPIR_Ireduce_scatter_block_intra_sched_pairwise(sendbuf, recvbuf, recvcount, datatype,
                                                            op, comm_ptr, s);
        MPIR_ERR_CHECK(mpi_errno);
    } else {    /* (!is_commutative) */

        if (MPL_is_pof2(comm_size, NULL)) {
            /* noncommutative, pof2 size */
            mpi_errno =
                MPIR_Ireduce_scatter_block_intra_sched_noncommutative(sendbuf, recvbuf, recvcount,
                                                                      datatype, op, comm_ptr, s);
            MPIR_ERR_CHECK(mpi_errno);
        } else {
            /* noncommutative and non-pof2, use recursive doubling. */
            mpi_errno =
                MPIR_Ireduce_scatter_block_intra_sched_recursive_doubling(sendbuf, recvbuf,
                                                                          recvcount, datatype, op,
                                                                          comm_ptr, s);
            MPIR_ERR_CHECK(mpi_errno);
        }
    }

  fn_exit:
    return mpi_errno;
  fn_fail:
    goto fn_exit;
}


int MPIR_Ireduce_scatter_block_inter_sched_auto(const void *sendbuf, void *recvbuf,
                                                MPI_Aint recvcount, MPI_Datatype datatype,
                                                MPI_Op op, MPIR_Comm * comm_ptr, MPIR_Sched_t s)
{
    int mpi_errno = MPI_SUCCESS;

    mpi_errno =
        MPIR_Ireduce_scatter_block_inter_sched_remote_reduce_local_scatterv(sendbuf, recvbuf,
                                                                            recvcount, datatype, op,
                                                                            comm_ptr, s);

    return mpi_errno;
}

int MPIR_Ireduce_scatter_block_sched_auto(const void *sendbuf, void *recvbuf, MPI_Aint recvcount,
                                          MPI_Datatype datatype, MPI_Op op, MPIR_Comm * comm_ptr,
                                          MPIR_Sched_t s)
{
    int mpi_errno = MPI_SUCCESS;

    if (comm_ptr->comm_kind == MPIR_COMM_KIND__INTRACOMM) {
        mpi_errno = MPIR_Ireduce_scatter_block_intra_sched_auto(sendbuf, recvbuf,
                                                                recvcount, datatype, op, comm_ptr,
                                                                s);
    } else {
        mpi_errno = MPIR_Ireduce_scatter_block_inter_sched_auto(sendbuf, recvbuf,
                                                                recvcount, datatype, op, comm_ptr,
                                                                s);
    }

    return mpi_errno;
}

int MPIR_Ireduce_scatter_block_sched_impl(const void *sendbuf, void *recvbuf, MPI_Aint recvcount,
                                          MPI_Datatype datatype, MPI_Op op, MPIR_Comm * comm_ptr,
                                          bool is_persistent, void **sched_p,
                                          enum MPIR_sched_type *sched_type_p)
{
    int mpi_errno = MPI_SUCCESS;
    int is_commutative = MPIR_Op_is_commutative(op);

    /* If the user picks one of the transport-enabled algorithms, branch there
     * before going down to the MPIR_Sched-based algorithms. */
    /* TODO - Eventually the intention is to replace all of the
     * MPIR_Sched-based algorithms with transport-enabled algorithms, but that
     * will require sufficient performance testing and replacement algorithms. */
    if (comm_ptr->comm_kind == MPIR_COMM_KIND__INTRACOMM) {
        switch (MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTRA_ALGORITHM) {
            /* *INDENT-OFF* */
            case MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTRA_ALGORITHM_gentran_recexch:
                MPII_COLLECTIVE_FALLBACK_CHECK(comm_ptr->rank, is_commutative, mpi_errno,
                                               "Ireduce_scatter_block gentran_recexch cannot be applied.\n");
                MPII_GENTRAN_CREATE_SCHED_P();
                mpi_errno =
                    MPIR_TSP_Ireduce_scatter_block_sched_intra_recexch(sendbuf, recvbuf, recvcount,
                                                                       datatype, op, comm_ptr,
                                                                       MPIR_CVAR_IREDUCE_SCATTER_BLOCK_RECEXCH_KVAL,
                                                                       *sched_p);
                break;

            case MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTRA_ALGORITHM_sched_noncommutative:
                MPII_SCHED_CREATE_SCHED_P();
                mpi_errno =
                    MPIR_Ireduce_scatter_block_intra_sched_noncommutative(sendbuf, recvbuf,
                                                                          recvcount, datatype, op,
                                                                          comm_ptr, *sched_p);
                break;

            case MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTRA_ALGORITHM_sched_pairwise:
                MPII_SCHED_CREATE_SCHED_P();
                mpi_errno =
                    MPIR_Ireduce_scatter_block_intra_sched_pairwise(sendbuf, recvbuf, recvcount,
                                                                    datatype, op, comm_ptr,
                                                                    *sched_p);
                break;

            case MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTRA_ALGORITHM_sched_recursive_halving:
                MPII_SCHED_CREATE_SCHED_P();
                mpi_errno =
                    MPIR_Ireduce_scatter_block_intra_sched_recursive_halving(sendbuf, recvbuf,
                                                                             recvcount, datatype,
                                                                             op, comm_ptr,
                                                                             *sched_p);
                break;

            case MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTRA_ALGORITHM_sched_recursive_doubling:
                MPII_SCHED_CREATE_SCHED_P();
                mpi_errno =
                    MPIR_Ireduce_scatter_block_intra_sched_recursive_doubling(sendbuf, recvbuf,
                                                                              recvcount, datatype,
                                                                              op, comm_ptr,
                                                                              *sched_p);
                break;

            case MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTRA_ALGORITHM_sched_auto:
                MPII_SCHED_CREATE_SCHED_P();
                mpi_errno = MPIR_Ireduce_scatter_block_intra_sched_auto(sendbuf, recvbuf, recvcount,
                                                                        datatype, op, comm_ptr,
                                                                        *sched_p);
                break;

            case MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTRA_ALGORITHM_auto:
                mpi_errno =
                    MPIR_Ireduce_scatter_block_allcomm_sched_auto(sendbuf, recvbuf, recvcount,
                                                                  datatype, op, comm_ptr,
                                                                  is_persistent, sched_p,
                                                                  sched_type_p);
                break;

            default:
                MPIR_Assert(0);
            /* *INDENT-ON* */
        }
    } else {
        switch (MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTER_ALGORITHM) {
            /* *INDENT-OFF* */
            case MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTER_ALGORITHM_sched_remote_reduce_local_scatterv:
                MPII_SCHED_CREATE_SCHED_P();
                mpi_errno =
                    MPIR_Ireduce_scatter_block_inter_sched_remote_reduce_local_scatterv(sendbuf,
                                                                                        recvbuf,
                                                                                        recvcount,
                                                                                        datatype,
                                                                                        op,
                                                                                        comm_ptr,
                                                                                        *sched_p);
                break;

            case MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTER_ALGORITHM_sched_auto:
                MPII_SCHED_CREATE_SCHED_P();
                mpi_errno = MPIR_Ireduce_scatter_block_inter_sched_auto(sendbuf, recvbuf, recvcount,
                                                                        datatype, op, comm_ptr,
                                                                        *sched_p);
                break;

            case MPIR_CVAR_IREDUCE_SCATTER_BLOCK_INTER_ALGORITHM_auto:
                mpi_errno =
                    MPIR_Ireduce_scatter_block_allcomm_sched_auto(sendbuf, recvbuf, recvcount,
                                                                  datatype, op, comm_ptr,
                                                                  is_persistent, sched_p,
                                                                  sched_type_p);
                break;

            default:
                MPIR_Assert(0);
            /* *INDENT-ON* */
        }
    }

    MPIR_ERR_CHECK(mpi_errno);
    goto fn_exit;

  fallback:
    if (comm_ptr->comm_kind == MPIR_COMM_KIND__INTRACOMM) {
        MPII_SCHED_CREATE_SCHED_P();
        mpi_errno = MPIR_Ireduce_scatter_block_intra_sched_auto(sendbuf, recvbuf, recvcount,
                                                                datatype, op, comm_ptr, *sched_p);
    } else {
        MPII_SCHED_CREATE_SCHED_P();
        mpi_errno = MPIR_Ireduce_scatter_block_inter_sched_auto(sendbuf, recvbuf, recvcount,
                                                                datatype, op, comm_ptr, *sched_p);
    }

  fn_exit:
    return mpi_errno;
  fn_fail:
    goto fn_exit;
}

int MPIR_Ireduce_scatter_block_impl(const void *sendbuf, void *recvbuf,
                                    MPI_Aint recvcount, MPI_Datatype datatype,
                                    MPI_Op op, MPIR_Comm * comm_ptr, MPIR_Request ** request)
{
    int mpi_errno = MPI_SUCCESS;

    *request = NULL;

    enum MPIR_sched_type sched_type;
    void *sched;
    mpi_errno = MPIR_Ireduce_scatter_block_sched_impl(sendbuf, recvbuf, recvcount, datatype, op,
                                                      comm_ptr, false, &sched, &sched_type);
    MPIR_ERR_CHECK(mpi_errno);

    MPII_SCHED_START(sched_type, sched, comm_ptr, request);

  fn_exit:
    return mpi_errno;
  fn_fail:
    goto fn_exit;
}

int MPIR_Ireduce_scatter_block(const void *sendbuf, void *recvbuf,
                               MPI_Aint recvcount, MPI_Datatype datatype,
                               MPI_Op op, MPIR_Comm * comm_ptr, MPIR_Request ** request)
{
    int mpi_errno = MPI_SUCCESS;
    void *in_recvbuf = recvbuf;
    void *host_sendbuf;
    void *host_recvbuf;

    MPIR_Coll_host_buffer_alloc(sendbuf, recvbuf, MPIR_Comm_size(comm_ptr) * recvcount, datatype,
                                &host_sendbuf, &host_recvbuf);
    if (host_sendbuf)
        sendbuf = host_sendbuf;
    if (host_recvbuf)
        recvbuf = host_recvbuf;

    if ((MPIR_CVAR_DEVICE_COLLECTIVES == MPIR_CVAR_DEVICE_COLLECTIVES_all) ||
        ((MPIR_CVAR_DEVICE_COLLECTIVES == MPIR_CVAR_DEVICE_COLLECTIVES_percoll) &&
         MPIR_CVAR_IREDUCE_SCATTER_BLOCK_DEVICE_COLLECTIVE)) {
        mpi_errno =
            MPID_Ireduce_scatter_block(sendbuf, recvbuf, recvcount, datatype, op, comm_ptr,
                                       request);
    } else {
        mpi_errno = MPIR_Ireduce_scatter_block_impl(sendbuf, recvbuf, recvcount, datatype, op,
                                                    comm_ptr, request);
    }

    MPIR_Coll_host_buffer_swap_back(host_sendbuf, host_recvbuf, in_recvbuf, recvcount, datatype,
                                    *request);

    return mpi_errno;
}

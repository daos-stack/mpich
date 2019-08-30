/*
 *  (C) 2006 by Argonne National Laboratory.
 *      See COPYRIGHT in top-level directory.
 *
 *  Portions of this code were written by Intel Corporation.
 *  Copyright (C) 2011-2017 Corporation.  Intel provides this material
 *  to Argonne National Laboratory subject to Software Grant and Corporate
 *  Contributor License Agreement dated February 8, 2012.
 */

#ifndef TSP_STUBTRAN_TYPES_H_INCLUDED
#define TSP_STUBTRAN_TYPES_H_INCLUDED

typedef struct MPII_Stubutil_sched_t {
    /* empty structures are invalid on some systems/compilers */
    int dummy;
} MPII_Stubutil_sched_t;

typedef int (*MPII_Stubutil_sched_issue_fn) (void *vtxp, int *done);
typedef int (*MPII_Stubutil_sched_complete_fn) (void *vtxp, int *is_completed);
typedef int (*MPII_Stubutil_sched_free_fn) (void *vtxp);

#endif /* TSP_STUBTRAN_TYPES_H_INCLUDED */

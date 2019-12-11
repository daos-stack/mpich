/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil ; -*- */
/*
 *  (C) 2017 by Argonne National Laboratory.
 *      See COPYRIGHT in top-level directory.
 */
/*
    Copyright 2019 Intel Corporation.

    This software and the related documents are Intel copyrighted materials, and
    your use of them is governed by the express license under which they were
    provided to you (License). Unless the License provides otherwise, you may
    not use, modify, copy, publish, distribute, disclose or transmit this
    software or the related documents without Intel's prior written permission.

    This software and the related documents are provided as is, with no express
    or implied warranties, other than those that are expressly stated in the
    License.
*/

#include "hydra_timeout.h"
#include "hydra_err.h"

static time_t get_current_time(void)
{
    return time(NULL);
}

void HYD_init_timeout(int sec, struct timeout_s *timeout)
{
    timeout->sec = sec;

    if (timeout->sec >= 0) {
        timeout->start_time = get_current_time();
    }
}

void HYD_set_alarm(struct timeout_s *timeout)
{
#ifdef HAVE_ALARM
    alarm(timeout->sec);
#endif /* HAVE_ALARM */
    timeout->start_time = get_current_time();
}

void HYD_handle_sigalrm(struct timeout_s *timeout)
{
    timeout->timed_out = 1;
}

int HYD_get_timeout_signal(struct timeout_s *timeout)
{
    return (timeout->signal > 0) ? timeout->signal : SIGKILL;
}

int HYD_get_time_left(struct timeout_s *timeout)
{
    if (timeout->start_time <= 0) {
        return -1;
    }

    int time_diff = (int) difftime(get_current_time(), timeout->start_time);

    int time_left = timeout->sec - time_diff;
    return (time_left > 0) ? time_left : 0;
}

void HYD_check_timed_out(struct timeout_s *timeout, int *exit_status)
{
    if (!timeout->timed_out) {
        return;
    }

    HYD_print_timeout_message(timeout);
    *exit_status |= 1;
}

void HYD_print_timeout_message(struct timeout_s *timeout)
{
    HYD_PRINT_NOPREFIX(stdout,
                       "MPIEXEC_TIMEOUT = %d second(s): job ending due to application timeout\n",
                       timeout->sec);
}

/* Copyright (C) 2015-2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update the \author in this file and detect-s7comm-s7commbuf.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "s7comm_s7commbuf" keyword to allow content
 * inspections on the decoded s7comm application layer buffers.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "app-layer-s7comm.h"
#include "detect-s7comm-s7commbuf.h"

static int DetectS7commS7commbufSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id);
#ifdef UNITTESTS
static void DetectS7commS7commbufRegisterTests(void);
#endif
static int g_s7comm_s7commbuf_id = 0;

void DetectS7commS7commbufRegister(void)
{
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].name = "s7comm_s7commbuf";
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].desc =
        "S7comm content modififier to match on the s7comm buffers";
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].Setup = DetectS7commS7commbufSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].RegisterTests =
        DetectS7commS7commbufRegisterTests;
#endif

    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].flags |= SIGMATCH_NOOPT;

    /* register inspect engines - these are called per signature */
    DetectAppLayerInspectEngineRegister2("s7comm_s7commbuf",
            ALPROTO_S7COMM, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerInspectEngineRegister2("s7comm_s7commbuf",
            ALPROTO_S7COMM, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);

    /* register mpm engines - these are called in the prefilter stage */
    DetectAppLayerMpmRegister2("s7comm_s7commbuf", SIG_FLAG_TOSERVER, 0,
            PrefilterGenericMpmRegister, GetData,
            ALPROTO_S7COMM, 0);
    DetectAppLayerMpmRegister2("s7comm_s7commbuf", SIG_FLAG_TOCLIENT, 0,
            PrefilterGenericMpmRegister, GetData,
            ALPROTO_S7COMM, 0);


    g_s7comm_s7commbuf_id = DetectBufferTypeGetByName("s7comm_s7commbuf");

    SCLogNotice("S7comm application layer detect registered.");
}

static int DetectS7commS7commbufSetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str)
{
    /* store list id. Content, pcre, etc will be added to the list at this
     * id. */
    s->init_data->list = g_s7comm_s7commbuf_id;

    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_S7COMM */
    if (DetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0)
        return -1;

    return 0;
}

/** \internal
 *  \brief get the data to inspect from the transaction.
 *  This function gets the data, sets up the InspectionBuffer object
 *  and applies transformations (if any).
 *
 *  \retval buffer or NULL in case of error
 */
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const S7commTransaction  *tx = (S7commTransaction *)txv;
        const uint8_t *data = NULL;
        uint32_t data_len = 0;

        if (flow_flags & STREAM_TOSERVER) {
            data = tx->request_buffer;
            data_len = tx->request_buffer_len;
        } else if (flow_flags & STREAM_TOCLIENT) {
            data = tx->response_buffer;
            data_len = tx->response_buffer_len;
        } else {
            return NULL; /* no buffer */
        }

        InspectionBufferSetup(buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-s7comm-s7commbuf.c"
#endif

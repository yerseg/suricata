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
 * \author Sergey Kazmin <yourname@domain>
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

// TODO: regex!!!

/**
 * \brief Regex for parsing the S7comm type string
 */
#define PARSE_REGEX_TYPE "^\\s*\"?\\s*unit\\s+([<>]?\\d+)(<>\\d+)?(,\\s*(.*))?\\s*\"?\\s*$"
static DetectParseRegex type_parse_regex;

/**
 * \brief Regex for parsing the S7comm function string
 */
#define PARSE_REGEX_FUNCTION "^\\s*\"?\\s*function\\s*\\d\\s*\"?\\s*$"
static DetectParseRegex function_parse_regex;
        
#ifdef UNITTESTS
static void DetectS7commS7commbufRegisterTests(void);
#endif

static int g_s7comm_id = 0;

static DetectS7comm *DetectS7commTypeParse(DetectEngineCtx *de_ctx, const char *s7commstr)
{
    SCEnter();
    DetectS7comm *s7comm = NULL;

    char    arg[MAX_SUBSTRINGS];
    int     ov[MAX_SUBSTRINGS], ret, res;

    ret = DetectParsePcreExec(&type_parse_regex, s7commstr, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1)
        goto error;

    res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 1, arg, MAX_SUBSTRINGS);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    if (ret > 3) {
        /* We have more S7comm option */
        const char *str_ptr;

        res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 4, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        if ((modbus = DetectModbusFunctionParse(de_ctx, str_ptr)) == NULL) {
            if ((modbus = DetectModbusAccessParse(de_ctx, str_ptr)) == NULL) {
                SCLogError(SC_ERR_PCRE_MATCH, "invalid modbus option");
                goto error;
            }
        }
    } else {
        /* We have only unit id Modbus option */
        modbus = (DetectModbus *) SCCalloc(1, sizeof(DetectModbus));
        if (unlikely(modbus == NULL))
            goto error;
    }

    /* We have a correct unit id option */
    modbus->unit_id = (DetectModbusValue *) SCCalloc(1, sizeof(DetectModbusValue));
    if (unlikely(modbus->unit_id == NULL))
        goto error;

    uint8_t idx;
    if (arg[0] == '>') { 
        idx = 1;
        modbus->unit_id->mode  = DETECT_MODBUS_GT;
    } else if (arg[0] == '<') {
        idx = 1;
        modbus->unit_id->mode  = DETECT_MODBUS_LT;
    } else {
        idx = 0;
    }
    if (StringParseUint16(&modbus->unit_id->min, 10, 0, (const char *) (arg + idx)) < 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Invalid value for "
                   "modbus min unit id: %s", (const char*)(arg + idx));
        goto error;
    }
    SCLogDebug("and min/equal unit id %d", modbus->unit_id->min);

    if (ret > 2) {
        res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 2, arg, MAX_SUBSTRINGS);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        if (*arg != '\0') {
            if (StringParseUint16(&modbus->unit_id->max, 10, 0, (const char *) (arg + 2)) < 0) {
                SCLogError(SC_ERR_INVALID_VALUE, "Invalid value for "
                           "modbus max unit id: %s", (const char*)(arg + 2));
                goto error;
            }
            modbus->unit_id->mode  = DETECT_MODBUS_RA;
            SCLogDebug("and max unit id %d", modbus->unit_id->max);
        }
    }

    SCReturnPtr(modbus, "DetectModbusUnitId");

error:
    if (modbus != NULL)
        DetectModbusFree(de_ctx, modbus);

    SCReturnPtr(NULL, "DetectModbus");
}

static DetectS7comm *DetectS7commFunctionParse(DetectEngineCtx *de_ctx, const char *s7commstr)
{

}

static int DetectS7commMatch(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{

}

static int DetectS7commSetup(DetectEngineCtx *de_ctx, Signature *s, const char *s7commstr)
{
    SCEnter();

    /* store list id. Content, pcre, etc will be added to the list at this
     * id. */
    s->init_data->list = g_s7comm_id;

    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_S7COMM */

    DetectS7comm    *s7comm = NULL;
    SigMatch        *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_S7COMM) != 0)
        SCReturnInt(-1);

    if ((s7comm = DetectS7commTypeParse(de_ctx, str)) == NULL) {
        if ((s7comm = DetectS7commFunctionParse(de_ctx, str)) == NULL) {
            SCLogError(SC_ERR_PCRE_MATCH, "invalid modbus option");
            if (modbus != NULL)
                DetectS7commFree(de_ctx, s7comm);

            if (sm != NULL)
                SCFree(sm);

            SCReturnInt(-1);
        }
    }

    /* Okay so far so good, lets get this into a SigMatch and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
    {
        if (modbus != NULL)
            DetectS7commFree(de_ctx, s7comm);

        if (sm != NULL)
            SCFree(sm);

        SCReturnInt(-1);
    }

    sm->type    = DETECT_AL_S7COMM_S7COMMBUF;
    sm->ctx     = (void *) s7comm;

    SigMatchAppendSMToList(s, sm, );

    SCReturnInt(0);
}

static void DetectS7commFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    DetectS7comm *s7comm = (DetectS7comm *) ptr;

    if (s7comm) {
        SCFree(s7comm);
    }
}

void DetectS7commS7commbufRegister(void)
{
    SCEnter();    

    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].name = "s7comm";
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].desc = "S7comm content modififier to match on the s7comm buffers";
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].Match = DetectS7commMatch;
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].Setup = DetectS7commSetup;
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].Free = DetectS7commFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].RegisterTests =
        DetectS7commS7commbufRegisterTests;
#endif

    sigmatch_table[DETECT_AL_S7COMM_S7COMMBUF].flags |= SIGMATCH_NOOPT;

    DetectSetupParseRegexes(PARSE_REGEX_TYPE, &type_parse_regex);
    DetectSetupParseRegexes(PARSE_REGEX_FUNCTION, &function_parse_regex);

    g_s7comm_id = DetectBufferTypeGetByName("s7comm");

    SCLogNotice("S7comm application layer detect registered.");
}

#ifdef UNITTESTS
#include "tests/detect-s7comm-s7commbuf.c"
#endif
